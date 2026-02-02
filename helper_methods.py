import logging
import warnings
import requests
import threading
import time
from rdflib import Graph
from urllib.parse import urlparse
from rdflib.plugins.sparql import prepareQuery
from rdflib.plugins.stores.sparqlstore import SPARQLStore
from SPARQLWrapper import SPARQLWrapper, JSON, XML, CSV, JSONLD

logging.getLogger().setLevel(logging.INFO)


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate if the URL is valid and return detailed error message.

    Args:
        url (str): The URL to validate

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if not url or not url.strip():
        return False, "URL cannot be empty"

    url = url.strip()
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            error_msg = f"Invalid URL format. Please provide a complete URL with protocol (http:// or https://)"
            logging.error(f"Invalid URL format: {url}")
            return False, error_msg

        if parsed.scheme not in ["http", "https"]:
            error_msg = f"Unsupported URL protocol '{parsed.scheme}'. Only HTTP and HTTPS are allowed"
            logging.error(f"Unsupported URL scheme: {parsed.scheme}")
            return False, error_msg
    except Exception as e:
        error_msg = f"Error parsing URL: {str(e)}"
        logging.error(f"Error parsing URL {url}: {e}")
        return False, error_msg

    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        if response.status_code == 405:
            response = requests.get(url, timeout=10, allow_redirects=True, stream=True)

        if 200 <= response.status_code <= 403:
            return True, ""
        else:
            error_msg = f"URL is not accessible (HTTP {response.status_code}). Please check the URL and try again"
            logging.error(f"URL returned status code {response.status_code}: {url}")
            return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error while validating URL: {str(e)}"
        logging.error(f"Unexpected error validating URL {url}: {e}")
        return False, error_msg


def validate_sparql_query(query: str) -> bool:
    """
    Validate a SPARQL query if it is syntactically correct

    Args:
        query (str): The SPARQL query to validate

    Returns:
        bool: True if the query is syntactically correct, False otherwise
    """
    try:
        prepareQuery(query)
        return True
    except Exception as e:
        logging.error(f"Invalid SPARQL syntax: {e}")
        return False


def check_sparql_endpoint_deprecated(endpoint_uri: str) -> bool:
    """
    Check if the SPARQL endpoint is accessible using rdflib.

    Args:
        endpoint_uri (str): The URI of the SPARQL endpoint.

    Returns:
        bool: True if the endpoint is accessible and responds correctly, False otherwise.
    """
    try:
        store = SPARQLStore(endpoint_uri)
        graph = Graph(store=store)
        test_query = """
        SELECT * WHERE { 
            ?s ?p ?o 
        } LIMIT 1
        """

        results = graph.query(test_query)
        list(results)

        logging.info(f"SPARQL endpoint {endpoint_uri} is accessible and working")
        return True

    except Exception as e:
        logging.error(f"Cannot access SPARQL endpoint {endpoint_uri}: {e}")
        return False


def check_sparql_endpoint(
    endpoint_uri: str,
    query: str = "SELECT * WHERE { ?s ?p ?o } LIMIT 1",
    return_result: bool = False,
    set_timeout: bool = False,
    timeout: int = 15,
) -> bool | tuple[bool, any]:
    """
    Check if the SPARQL endpoint is accessible using SPARQLWrapper with a return format of JSON, XML, CSV, JSON-LD.

    Args:
        endpoint_uri (str): The URI of the SPARQL endpoint.

    Returns:
        str: The name of the return format that works, or False if no return format works.
    """
    return_formats = [("JSON", JSON), ("XML", XML), ("CSV", CSV), ("JSON-LD", JSONLD)]
    for return_format_name, return_format in return_formats:
        try:
            sparql = SPARQLWrapper(endpoint_uri)
            # set timeout to 15 seconds for each validation of sparql endpoint
            if set_timeout:
                sparql.setTimeout(timeout)
            sparql.setReturnFormat(return_format)
            sparql.setQuery(query)

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                response = sparql.query().convert()

                for warning in w:
                    if "unknown response content type 'text/html'" in str(
                        warning.message
                    ):
                        raise Exception(
                            f"SPARQL endpoint {endpoint_uri} returned HTML instead of {return_format_name}"
                        )

            logging.info(
                f"SPARQL endpoint {endpoint_uri} is accessible and working with {return_format_name} return format"
            )
            return (True, response) if return_result else True

        except TimeoutError as e:
            logging.warning(f"SPARQL endpoint {endpoint_uri} is timing out")
            return (True, "") if return_result else True
        except Exception as e:
            logging.error(
                f"Cannot access SPARQL endpoint {endpoint_uri} with {return_format_name} return format: {e}"
            )
            continue

    # If SPARQL formats fail, try treating as HTTP endpoint
    try:
        params = {
            "query": query,
            "format": "text/html"
        }
        response = requests.get(endpoint_uri, timeout=60, params=params)
        if 200 <= response.status_code < 300:
            logging.info(
                f"SPARQL endpoint {endpoint_uri} is accessible as HTTP endpoint"
            )
            return (True, "") if return_result else True
    except Exception as e:
        logging.error(f"Cannot access endpoint {endpoint_uri} as HTTP: {e}")

    logging.error(
        f"Cannot access SPARQL endpoint {endpoint_uri} with any return format or as HTTP"
    )
    return False


def escape_string(text: str) -> str:
    """Escape special characters in strings for Turtle format"""
    if not text:
        return ""
    return text.replace('"', '\\"').replace("\\", "\\\\").replace("\n", "\\n")


def execute_sparql_query(
    query: str, endpoint_uri: str, limit: int = 20, timeout: int = 120
):
    """Run SPARQL query against endpoint and return list of bindings as dictionaries.

    Args:
        query (str): SPARQL query to execute.
        endpoint_uri (str): SPARQL endpoint URL.
        limit (int, optional): Maximum number of results to return. Defaults to 20.
        timeout (int, optional): Timeout in seconds. Defaults to 120.

    Returns:
        List[dict]: Query results where each dict maps variable names to their string values.

    Raises:
        TimeoutError: If the query takes longer than the specified timeout.
    """
    result = None
    error = None
    completed = threading.Event()

    def execute_query():
        nonlocal result, error
        try:
            # If user query lacks LIMIT, optionally append a limit to avoid huge payloads
            lowered = query.lower()
            if "limit" not in lowered:
                query_to_run = f"{query.strip()} LIMIT {limit}"
            else:
                query_to_run = query

            # Use check_sparql_endpoint directly to execute the query
            endpoint_check = check_sparql_endpoint(
                endpoint_uri,
                query_to_run,
                return_result=True,
                set_timeout=True,
                timeout=timeout,
            )

            if not endpoint_check or not endpoint_check[0]:
                error = Exception(f"Failed to query SPARQL endpoint {endpoint_uri}")
                return

            response = endpoint_check[1]
            formatted_results = []

            if isinstance(response, dict):
                if "results" in response and "bindings" in response["results"]:
                    # process SPARQL response format
                    bindings = response["results"]["bindings"]
                    counter = 0
                    for binding in bindings:
                        if counter >= limit:
                            break
                        formatted_row = {}
                        for var, val in binding.items():
                            if isinstance(val, dict) and "value" in val:
                                formatted_row[var] = str(val["value"])
                            else:
                                formatted_row[var] = str(val)
                        formatted_results.append(formatted_row)
                        counter += 1
                else:
                    formatted_results = [response] if response else []
            elif isinstance(response, str):
                formatted_results = [{"result": response}]
            else:
                formatted_results = [{"result": str(response)}]

            result = formatted_results
        except Exception as e:
            error = e
        finally:
            completed.set()

    thread = threading.Thread(target=execute_query)
    thread.daemon = True
    thread.start()

    if not completed.wait(timeout=timeout):
        raise TimeoutError(f"SPARQL query execution timed out after {timeout} seconds")

    if error:
        raise error

    return result
