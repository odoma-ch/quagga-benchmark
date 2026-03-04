import io
import os
import logging
import requests
import httpx
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from typing import Optional, List
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from rdflib import Graph, Namespace, Literal, URIRef
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi import FastAPI, Request, Form, Depends, Response, HTTPException, status
from datetime import datetime
from concurrent.futures import TimeoutError

import database
import data_models
import helper_methods
import const


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))

app.mount("/templates", StaticFiles(directory="templates"), name="templates")

logging.getLogger().setLevel(logging.INFO)
templates = Jinja2Templates(directory="templates")

BASE_URI = "http://example.org/question-kg-linker/"
EXYGEN_BASE_URL = (
    "https://exygen.graphia-ssh.eu/"
)
EXYGEN_KG_METADATA_URL = f"{EXYGEN_BASE_URL}get_kg_metadata"
EXYGEN_GENERATE_KG_DATA_URL = f"{EXYGEN_BASE_URL}generate_kg_metadata"
QKL = Namespace(BASE_URI)

# for setting up oauth for github
oauth = OAuth()
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    client_kwargs={"scope": "user:email"},
)

# for setting up oauth for orcid
oauth.register(
    name="orcid",
    client_id=os.getenv("ORCID_CLIENT_ID"),
    client_secret=os.getenv("ORCID_CLIENT_SECRET"),
    authorize_url="https://orcid.org/oauth/authorize",
    access_token_url="https://orcid.org/oauth/token",
    client_kwargs={"scope": "/authenticate"},
)


# for setting up oauth for operas
oauth.register(
    name="operas",
    client_id=os.getenv("OPERAS_CLIENT_ID"),
    client_secret=os.getenv("OPERAS_CLIENT_SECRET"),
    authorize_url="https://id.operas-eu.org/oauth2/authorize",
    access_token_url="https://id.operas-eu.org/oauth2/token",
    client_kwargs={"scope": "openid email"},
)


def generate_pkce():
    """Generate PKCE code verifier and code challenge for OAuth2 PKCE flow using authlib."""
    # Generate code verifier (43-128 characters, URL-safe)
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    )

    # Generate code challenge using authlib's built-in function
    code_challenge = create_s256_code_challenge(code_verifier)

    return code_verifier, code_challenge


async def get_current_user(request: Request):
    """Get the current user from the session."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.on_event("startup")
def on_startup():
    """Initialize the database."""
    database.init_db()


@app.get("/")
async def redirect_to_home(request: Request):
    """Redirect to the home page."""
    return RedirectResponse(url="/home")


@app.get("/contribute")
async def read_root(request: Request):
    """Homepage with submission forms."""
    user = request.session.get("user")
    current_month = datetime.now().strftime("%B")
    kg_metadata = database.get_all_kg_metadata()
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        "contribute.html",
        {
            "request": request,
            "user": user,
            "kg_metadata": kg_metadata,
            "current_month": current_month,
        },
    )


@app.get("/login")
async def login(request: Request):
    """Check if user is already logged in if not show login page or redirect to GitHub OAuth."""
    user = request.session.get("user")
    if user:
        return RedirectResponse(url="/")

    # If github=true in query params, proceed with OAuth
    if request.query_params.get("github") == "true":
        redirect_uri = request.url_for("auth_github")
        return await oauth.github.authorize_redirect(
            request, redirect_uri, prompt="consent", approval_prompt="force"
        )

    if request.query_params.get("orcid") == "true":
        redirect_uri = request.url_for("auth_orcid")
        print("redirecting to orcid")
        return await oauth.orcid.authorize_redirect(request, redirect_uri)

    if request.query_params.get("operas") == "true":
        redirect_uri = request.url_for("auth_operasid")
        # Ensure HTTPS for production/deployed environments
        redirect_uri = str(redirect_uri).replace("http://", "https://")
        # Use authlib's OAuth2Session with proper PKCE support
        client = OAuth2Session(
            client_id=os.getenv("OPERAS_CLIENT_ID"),
            redirect_uri=str(redirect_uri),
            scope=["openid", "email"],
        )

        # Generate PKCE parameters using authlib
        code_verifier, code_challenge = generate_pkce()
        request.session["operas_pkce_code_verifier"] = code_verifier
        authorization_url, state = client.create_authorization_url(
            "https://id.operas-eu.org/oauth2/authorize",
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )
        request.session["operas_oauth_state"] = state
        return RedirectResponse(url=authorization_url)

    # Otherwise show the login page
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/auth/github")
async def auth_github(request: Request):
    """Authenticate the user and redirect to home page."""
    try:
        token = await oauth.github.authorize_access_token(request)
        resp = await oauth.github.get("https://api.github.com/user", token=token)
        user = resp.json()

        emails_resp = await oauth.github.get(
            "https://api.github.com/user/emails", token=token
        )
        emails = emails_resp.json()

        primary_email = None
        for email in emails:
            if email.get("primary"):
                primary_email = email.get("email")
                break

        user["email"] = primary_email if primary_email else user["login"]
        request.session["type"] = "github"
        request.session["user"] = user

        return RedirectResponse(url="/contribute")
    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return {"error": str(e)}


@app.get("/auth/operasid")
async def auth_operasid(request: Request):
    """Authenticate the user and redirect to home page."""
    try:
        # Verify state parameter for CSRF protection
        received_state = request.query_params.get("state")
        stored_state = request.session.pop("operas_oauth_state", None)
        if not received_state or received_state != stored_state:
            return {"error": "OAuth state mismatch - possible CSRF attack"}

        # Get authorization code from query parameters
        auth_code = request.query_params.get("code")
        if not auth_code:
            return {"error": f"Authorization failed: {error} - {error_description}"}

        # Retrieve the PKCE code verifier from session
        code_verifier = request.session.pop("operas_pkce_code_verifier", None)
        if not code_verifier:
            return {"error": "PKCE code verifier missing"}

        # Ensure HTTPS for the redirect URI
        redirect_uri = request.url_for("auth_operasid")
        redirect_uri = str(redirect_uri).replace("http://", "https://")

        client = OAuth2Session(
            client_id=os.getenv("OPERAS_CLIENT_ID"),
            client_secret=os.getenv("OPERAS_CLIENT_SECRET"),
            redirect_uri=str(redirect_uri),
        )
        callback_url = str(request.url)

        try:
            token = client.fetch_token(
                "https://id.operas-eu.org/oauth2/token",
                authorization_response=callback_url,
                code_verifier=code_verifier,
            )
            access_token = token.get("access_token")
            if not access_token:
                return {"error": "No access token received from OPERAS"}

            # Get user information using the access token
            user_response = requests.get(
                "https://id.operas-eu.org/oauth2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if user_response.status_code != 200:
                return {
                    "error": f"Failed to get user information: {user_response.status_code}"
                }
            user = user_response.json()
        except Exception as token_error:
            logging.error(f"Token exchange error: {token_error}")
            return {"error": f"Token exchange failed: {str(token_error)}"}

        primary_email = user.get("email")
        user["email"] = (
            primary_email if primary_email else user.get("login", user.get("sub", ""))
        )
        user["login"] = primary_email or user.get("sub", "")
        request.session["type"] = "operas"
        request.session["user"] = user

        return RedirectResponse(url="/contribute")
    except Exception as e:
        logging.error(f"Authentication error in OPERAS: {str(e)}")
        return {"error": str(e)}


@app.get("/auth/orcid")
async def auth_orcid(request: Request):
    try:
        token = await oauth.orcid.authorize_access_token(request)
        orcid_id = token.get("orcid")
        access_token = token.get("access_token")
        name = token.get("name")

        email = None
        if orcid_id:
            try:
                response = requests.get(
                    f"https://pub.orcid.org/v3.0/{orcid_id}/email",
                    headers={"Accept": "application/json"},
                )

                if response.status_code == 200:
                    email_data = response.json()
                    emails = email_data.get("email", [])

                    for email_entry in emails:
                        if email_entry.get("visibility") == "public":
                            email = email_entry.get("email")
                            break

            except Exception as e:
                logging.error(f"Error fetching ORCID email: {e}")

        request.session["type"] = "orcid"
        request.session["email"] = email if email else orcid_id

        request.session["user"] = {
            "orcid_id": orcid_id,
            "login": email if email else name,
            "email": email if email else orcid_id,
        }
        request.session["type"] = "orcid"
        request.session["user"][
            "avatar_url"
        ] = f'https://ui-avatars.com/api/?name={request.session["user"]["login"]}&background=0D8ABC&color=fff&rounded=true'

        return RedirectResponse(url="/contribute")
    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return {"error": str(e)}


@app.get("/logout")
async def logout(request: Request):
    """Log out the user and redirect to login page with a success message."""
    request.session.pop("user", None)
    return RedirectResponse(url="/login?logged_out=true")


@app.post("/submit_query")
async def submit_query(
    request: Request,
    kg_endpoint: str = Form(...),
    nl_question: str = Form(...),
    sparql_query: str = Form(None),
    kg_name: str = Form(None),
    kg_description: str = Form(None),
    kg_about_page: str = Form(None),
    domains: List[str] = Form(None),
    source: str = Form(None),
    is_dump_url: bool = Form(False),
    user: dict = Depends(get_current_user),
):
    """Handles submission of NL question + optional SPARQL query + KG endpoint."""
    try:
        # Validate endpoint based on whether it's a dump URL or SPARQL endpoint
        if is_dump_url:
            # For data dump URLs, use general URL validation
            is_valid, error_message = helper_methods.validate_url(kg_endpoint)
            if not is_valid:
                return JSONResponse(
                    {
                        "status": "error",
                        "message": f"Invalid data dump URL: {error_message}",
                    },
                    status_code=400,
                )
        else:
            # For SPARQL endpoints, use SPARQL-specific validation
            if not helper_methods.check_sparql_endpoint(kg_endpoint, set_timeout=True):
                return JSONResponse(
                    {"status": "error", "message": "Invalid SPARQL endpoint"},
                    status_code=400,
                )

        # Only validate SPARQL query if it's provided and not a dump URL
        if sparql_query and sparql_query.strip() and not is_dump_url:
            if not helper_methods.validate_sparql_query(sparql_query):
                return JSONResponse(
                    {"status": "error", "message": "Invalid SPARQL query"},
                    status_code=400,
                )

        if not database.get_if_endpoint_exists(kg_endpoint):
            # Validate about_page URL if this is a new custom endpoint
            if kg_about_page and kg_about_page.strip():
                is_valid, error_msg = helper_methods.validate_url(kg_about_page.strip())
                if not is_valid:
                    return JSONResponse(
                        {
                            "status": "error",
                            "message": f"About page URL error: {error_msg}",
                        },
                        status_code=400,
                    )
            else:
                # About page is mandatory for custom KG endpoints
                return JSONResponse(
                    {
                        "status": "error",
                        "message": "About page URL is required for custom knowledge graphs",
                    },
                    status_code=400,
                )

            database.insert_kg_endpoint(
                kg_name,
                kg_description,
                kg_endpoint,
                kg_about_page.strip(),
                domains,
                is_dump_url,
            )

        if source and source.strip():
            is_valid, error_msg = helper_methods.validate_url(source)
            if not is_valid:
                return JSONResponse(
                    {"status": "error", "message": f"Source URL error: {error_msg}"},
                    status_code=400,
                )

        database.insert_submission(
            kg_endpoint=kg_endpoint,
            nl_question=nl_question,
            email=user["email"],
            sparql_query=(
                sparql_query if sparql_query and sparql_query.strip() else None
            ),
            source=(source if source and source.strip() else None),
        )

        # Return appropriate message based on whether SPARQL was provided
        if sparql_query and sparql_query.strip():
            message = "Question and SPARQL query submitted successfully"
        else:
            message = "Question submitted successfully."

        return JSONResponse({"status": "success", "message": message})
    except Exception as e:
        logging.info(f"Error submitting query: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.post("/validate_endpoint")
async def validate_endpoint(
    request: Request,
    endpoint_url: str = Form(...),
    is_dump_url: bool = Form(False),
    user: dict = Depends(get_current_user),
):
    """Validates if a SPARQL endpoint or data dump URL is accessible and working."""
    try:
        if not endpoint_url or not endpoint_url.strip():
            return JSONResponse(
                {"status": "error", "message": "Endpoint URL is required"},
                status_code=400,
            )

        endpoint_url = endpoint_url.strip()

        if is_dump_url:
            is_valid, error_message = helper_methods.validate_url(endpoint_url)

            if is_valid:
                return JSONResponse(
                    {
                        "status": "success",
                        "message": "Data dump URL is accessible and working correctly",
                    }
                )
            else:
                return JSONResponse(
                    {
                        "status": "error",
                        "message": f"Data dump URL validation failed: {error_message}",
                    }
                )
        else:
            is_valid = helper_methods.check_sparql_endpoint(
                endpoint_url, set_timeout=True
            )

            if is_valid:
                return JSONResponse(
                    {
                        "status": "success",
                        "message": "SPARQL endpoint is accessible and working correctly",
                    }
                )
            else:
                return JSONResponse(
                    {
                        "status": "error",
                        "message": "SPARQL endpoint is not accessible or not responding correctly. Please check the URL and try again.",
                    }
                )

    except Exception as e:
        logging.error(f"Error validating endpoint: {e}")
        return JSONResponse(
            {
                "status": "error",
                "message": "An error occurred while validating the endpoint",
            },
            status_code=500,
        )


@app.post("/validate_query")
async def validate_query(
    request: Request,
    sparql_query: str = Form(...),
    endpoint_url: str = Form(...),
    user: dict = Depends(get_current_user),
):
    """Validate SPARQL query syntax and, if valid, execute it against the given endpoint."""
    try:
        if not sparql_query or not sparql_query.strip():
            return JSONResponse(
                {"status": "error", "message": "SPARQL query is required"},
                status_code=400,
            )

        if not endpoint_url or not endpoint_url.strip():
            return JSONResponse(
                {"status": "error", "message": "Endpoint URL is required"},
                status_code=400,
            )

        kg_metadata = database.get_all_kg_metadata(for_one=True, endpoint=endpoint_url)
        if kg_metadata and kg_metadata.get("is_dump"):
            if not helper_methods.validate_sparql_query(sparql_query.strip()):
                return JSONResponse(
                    {
                        "status": "error",
                        "message": "Invalid SPARQL query syntax",
                    },
                    status_code=400,
                )
            else:
                return JSONResponse(
                    {
                        "status": "success",
                        "message": "Query is syntactically correct",
                    },
                    status_code=200,
                )

        # Check endpoint accessibility (relax this requirement given it will already be validated)
        # if not helper_methods.check_sparql_endpoint(endpoint_url):
        #     return JSONResponse(
        #         {
        #             "status": "error",
        #             "message": "Endpoint is not accessible or not responding correctly.",
        #         },
        #         status_code=400,
        #     )

        # Validate syntax first
        if not helper_methods.validate_sparql_query(sparql_query.strip()):
            database.insert_validation_result(
                endpoint=endpoint_url.strip(),
                validation_status="error",
                validation_message="Invalid SPARQL query syntax",
                username=user["email"],
                sparql_query=sparql_query.strip(),
                query_result="error",
            )
            return JSONResponse(
                {"status": "error", "message": "Invalid SPARQL query syntax"},
                status_code=400,
            )
        # Execute query and limit results; log output on server
        logging.info(f"Executing SPARQL query now")
        try:
            results = helper_methods.execute_sparql_query(
                sparql_query.strip(), endpoint_url.strip(), timeout=120
            )
            database.insert_validation_result(
                endpoint=endpoint_url.strip(),
                validation_status="success",
                validation_message="Query executed successfully",
                username=user["email"],
                sparql_query=sparql_query.strip(),
                query_result=str(results),
            )
            logging.info("SPARQL validation result has been run")
        except TimeoutError as e:
            database.insert_validation_result(
                endpoint=endpoint_url.strip(),
                validation_status="timeout",
                validation_message=f"Query execution timed out after 120 seconds: {e}",
                username=user["email"],
                sparql_query=sparql_query.strip(),
                query_result="timeout",
            )
            logging.warning(f"SPARQL query timed out: {e}")
            return JSONResponse(
                {
                    "status": "success",
                    "message": "Query saved successfully in the database but timed out.",
                },
                status_code=200,
            )
        except Exception as e:
            database.insert_validation_result(
                endpoint=endpoint_url.strip(),
                validation_status="error",
                validation_message=f"Failed to run query: {e}",
                username=user["email"],
                sparql_query=sparql_query.strip(),
                query_result="error",
            )
            return JSONResponse(
                {"status": "error", "message": f"Failed to run query: {e}"},
                status_code=500,
            )

        return JSONResponse(
            {"status": "success", "message": "Query executed successfully"}
        )

    except Exception as e:
        logging.error(f"Error validating/executing SPARQL query: {e}")
        database.insert_validation_result(
            endpoint=endpoint_url.strip() if endpoint_url else "",
            validation_status="error",
            validation_message="An error occurred while processing the query",
            username=user["email"],
            sparql_query=sparql_query.strip() if sparql_query else "",
            query_result="error",
        )
        return JSONResponse(
            {
                "status": "error",
                "message": "An error occurred while processing the query",
            },
            status_code=500,
        )


@app.get("/trigger_modification", include_in_schema=False)
async def trigger_modification(
    request: Request,
    id_submission: str,
    user: dict = Depends(get_current_user),
):
    """Triggers the modification of a submission."""
    try:
        submission = database.get_submission(id_submission)
        logging.info(f"Submission: {submission}")
        return templates.TemplateResponse(
            "modify_form.html",
            {"request": request, "submission": submission, "user": user},
        )
    except Exception as e:
        logging.info(f"Error modifying submission: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.post("/modify_db_submission", include_in_schema=False)
async def modify_db_submission(
    request: Request,
    id_submission: str = Form(...),
    kg_endpoint: str = Form(...),
    nl_question: Optional[str] = Form(None),
    updated_sparql_query: Optional[str] = Form(None),
    user: dict = Depends(get_current_user),
):
    """Handles modification of a submission."""
    try:
        if updated_sparql_query:
            if not helper_methods.validate_sparql_query(updated_sparql_query):
                return JSONResponse(
                    {"status": "error", "message": "Invalid SPARQL query"},
                    status_code=500,
                )
        database.modify_submission(
            kg_endpoint, id_submission, user["email"], nl_question, updated_sparql_query
        )
        return JSONResponse(
            {
                "status": "success",
                "message": "Submission for SPARQL query modified successfully",
            }
        )
    except Exception as e:
        logging.info(f"Error modifying submission: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.get("/browse")
async def browse_page(request: Request):
    """Public browse page that lists all submissions from all KG endpoints."""
    user = request.session.get("user")

    # Check if user wants to filter by their contributions
    show_my_contributions = request.query_params.get("my_contributions") == "true"

    # Get current month for footer
    current_month = datetime.now().strftime("%B")

    # Fetch list of knowledge graph metadata entries
    if user and show_my_contributions:
        kg_list = database.get_kg_metadata_with_user_contributions(user["email"])
    else:
        kg_list = database.get_all_kg_metadata()

    # Calculate domain-specific KG counts (count of KGs per domain, not submissions)
    domain_counts = {}
    for domain_code in const.DISCIPLINE_DOMAINS.keys():
        domain_counts[domain_code] = 0

    # Count KGs for each domain (each KG counts as 1 regardless of submission count)
    for kg_data in kg_list:
        if kg_data.get("domains"):
            kg_domains = [d.strip() for d in kg_data["domains"].split(",")]

            # Add 1 to each domain this KG belongs to
            for domain_code in kg_domains:
                if domain_code in domain_counts:
                    domain_counts[domain_code] += 1

    # Calculate submission stats for each KG
    for endpoint_data in kg_list:
        endpoint = endpoint_data["endpoint"]
        submissions = database.get_submissions_by_kg(endpoint)

        total_submissions = len(submissions)
        query_pairs = sum(
            1
            for sub in submissions
            if sub.get("sparql_query") and sub.get("sparql_query").strip()
        )
        questions_only = total_submissions - query_pairs

        endpoint_data["total_submissions"] = total_submissions
        endpoint_data["query_pairs"] = query_pairs
        endpoint_data["questions_only"] = questions_only

    # The browse landing page now shows one card per knowledge graph.  We still pass an
    # empty ``submissions`` list so that template logic relying on the variable does not break.
    return templates.TemplateResponse(
        "submissions.html",
        {
            "request": request,
            "user": user,
            "submissions": [],  # No individual submissions on the landing page
            "kg_list": kg_list,
            "kg_name": "Knowledge Graphs",
            "kg_description": "Browse the available knowledge graphs below and click to view their submissions.",
            "is_browse_page": True,
            "domain_map": const.DISCIPLINE_DOMAINS,
            "domain_counts": domain_counts,
            "show_my_contributions": show_my_contributions,
            "current_month": current_month,
        },
    )


@app.get("/browse/{kg_endpoint:path}")
async def browse_submissions_for_kg(request: Request, kg_endpoint: str):
    """Public page that lists all submissions for a specific KG endpoint."""
    user = request.session.get("user")  # Optional user for conditional UI
    current_month = datetime.now().strftime("%B")
    submissions = database.get_submissions_by_kg(kg_endpoint)
    kg_metadata = database.get_all_kg_metadata(for_one=True, endpoint=kg_endpoint)
    return templates.TemplateResponse(
        "submissions.html",
        {
            "request": request,
            "user": user,
            "submissions": submissions,
            "endpoint": kg_endpoint,
            "kg_name": kg_metadata["name"],
            "kg_description": kg_metadata["description"],
            "kg_about_page": kg_metadata["about_page"],
            "is_dump": kg_metadata.get("is_dump", False),
            "is_browse_page": False,
            "current_month": current_month,
        },
    )


@app.get("/get_kg_metadata")
async def get_kg_metadata(kg_name: str, kg_endpoint_url: str):
    if not kg_name or not kg_endpoint_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="kg_name and kg_endpoint_url are required.",
        )

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            upstream = await client.get(
                EXYGEN_KG_METADATA_URL,
                params={"kg_name": kg_name, "kg_endpoint_url": kg_endpoint_url},
            )
    except httpx.RequestError as exc:
        logging.error(f"KG metadata upstream request failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to reach metadata service.",
        )

    if upstream.status_code != status.HTTP_200_OK:
        return Response(status_code=upstream.status_code)

    try:
        payload = upstream.json()
    except ValueError:
        logging.error("KG metadata upstream returned non-JSON payload.")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Metadata service returned invalid JSON.",
        )

    return JSONResponse(content=payload, status_code=status.HTTP_200_OK)


@app.post("/generate_kg_data", status_code=status.HTTP_204_NO_CONTENT)
async def generate_kg_data(kg_name: str, kg_endpoint_url: str):
    if not kg_name or not kg_endpoint_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="kg_name and kg_endpoint_url are required.",
        )

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            await client.post(
                EXYGEN_GENERATE_KG_DATA_URL,
                json={"kg_name": kg_name, "kg_endpoint_url": kg_endpoint_url},
            )
    except httpx.RequestError as exc:
        logging.warning(f"KG generate data upstream request failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to reach generate data service.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/list")
async def list_kglite_endpoints(
    request: Request, user: dict = Depends(get_current_user)
):
    """Lists unique KG endpoints with submissions. Protected route for logged-in users."""
    current_month = datetime.now().strftime("%B")
    kg_endpoints = database.get_unique_kg_endpoints()
    kg_metadata = database.get_all_kg_metadata()

    for endpoint_data in kg_metadata:
        endpoint = endpoint_data["endpoint"]
        submissions = database.get_submissions_by_kg(endpoint)

        total_submissions = len(submissions)
        query_pairs = sum(
            1
            for sub in submissions
            if sub.get("sparql_query") and sub.get("sparql_query").strip()
        )
        questions_only = total_submissions - query_pairs

        endpoint_data["total_submissions"] = total_submissions
        endpoint_data["query_pairs"] = query_pairs
        endpoint_data["questions_only"] = questions_only

    return templates.TemplateResponse(
        "contribute.html",
        {
            "request": request,
            "user": user,
            "kg_endpoints": kg_endpoints,
            "kg_metadata": kg_metadata,
            "current_month": current_month,
        },
    )


@app.get("/list/{kg_endpoint:path}")
async def list_submissions_for_kg(
    request: Request, kg_endpoint: str, user: dict = Depends(get_current_user)
):
    """Lists all submissions for a specific KG endpoint. Protected route for logged-in users."""
    submissions = database.get_submissions_by_kg(kg_endpoint)
    kg_metadata = database.get_all_kg_metadata(for_one=True, endpoint=kg_endpoint)
    return templates.TemplateResponse(
        "submissions.html",
        {
            "request": request,
            "user": user,
            "submissions": submissions,
            "endpoint": kg_endpoint,
            "kg_name": kg_metadata["name"],
            "kg_description": kg_metadata["description"],
            "kg_about_page": kg_metadata["about_page"],
            "is_dump": kg_metadata.get("is_dump", False),
        },
    )


@app.get("/export", include_in_schema=False)
async def export_submissions_rdf(
    request: Request, user: dict = Depends(get_current_user)
):
    """Exports all submissions as RDF (Turtle format)."""
    all_submissions = database.get_all_submissions()

    # create the content of the rdf file in a specified format
    # reference: https://github.com/sib-swiss/sparql-examples
    rdf_content = """
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix schema: <http://schema.org/> .
@prefix qkl: <http://example.org/question-kg-linker/> .
"""

    for sub in all_submissions:
        submission_id = sub["id"]
        comment = (
            "SPARQL - Natural language question pair"
            if sub["sparql_query"]
            else "Natural Language Question"
        )

        rdf_content += f"""qkl:{submission_id} .
\ta sh:SPARQLExecutable, sh:SPARQLSelectExecutable ;
\trdfs:comment "{comment}" ;
\tsh:prefixes _:sparql_examples_prefixes ;
"""

        if sub["sparql_query"]:
            rdf_content += f'\tsh:select """{helper_methods.escape_string(sub["sparql_query"])}""" ;\n'

        rdf_content += f'\tschema:target <{sub["kg_endpoint"]}> ;\n'
        rdf_content += (
            f'\tqkl:nlQuestion "{helper_methods.escape_string(sub["nl_question"])}" ;\n'
        )
        rdf_content += ".\n\n"

    return Response(content=rdf_content.encode("utf-8"), media_type="text/turtle")


@app.get("/home")
async def home_page(request: Request):
    """
    Home page with statistics about the crowdsourcing project.
    This page is the default page for the application.
    This is a public endpoint.
    """
    try:
        # Get current user (optional for public access)
        user = request.session.get("user")

        # Get current date
        current_date = datetime.now().strftime("%B %d, %Y")
        current_month = datetime.now().strftime("%B")

        # Get statistics from database
        all_submissions = database.get_all_submissions()

        # Calculate statistics
        n_queries = sum(
            1
            for sub in all_submissions
            if sub.get("sparql_query") and sub.get("sparql_query").strip()
        )
        n_questions = len(all_submissions) - n_queries
        n_contributors = len(
            set(
                sub.get("username", "")
                for sub in all_submissions
                if sub.get("username")
            )
        )
        n_kgs = len(database.get_unique_kg_endpoints())

        return templates.TemplateResponse(
            "home.html",
            {
                "request": request,
                "user": user,
                "current_date": current_date,
                "current_month": current_month,
                "n_queries": n_queries,
                "n_questions": n_questions,
                "n_contributors": n_contributors,
                "n_kgs": n_kgs,
            },
        )
    except Exception as e:
        logging.error(f"Error loading home page: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@app.get("/faq")
async def faq_page(request: Request):
    """
    FAQ page with frequently asked questions.
    This page is a public endpoint.
    """
    # Get current user (optional for public access)
    user = request.session.get("user")
    current_month = datetime.now().strftime("%B")
    return templates.TemplateResponse(
        "faq.html", {"request": request, "user": user, "current_month": current_month}
    )
