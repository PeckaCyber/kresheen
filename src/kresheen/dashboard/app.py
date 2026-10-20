"""FastAPI app factory for the Kresheen dashboard.

React SPA (see `frontend/`) against a JSON API (`/api/*` routers).

This factory serves the built SPA (`frontend/dist/`) for any non-API route
so client-side routing (React Router) still works on a hard refresh or a
deep link, and the `/api/*` JSON API every route module in this package
implements.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from kresheen.dashboard.audit import AuditMiddleware
from kresheen.dashboard.body_limit import BodySizeLimitMiddleware
from kresheen.dashboard.login_throttle import LoginThrottle
from kresheen.dashboard.routes import (
    api_agent_config,
    api_applications,
    api_audit,
    api_auth,
    api_capabilities,
    api_dashboard,
    api_groups,
    api_intake,
    api_report,
    api_settings_ai,
    api_threat_explain,
    api_threat_kb,
    api_threats,
    api_tokens,
    api_users,
)
from kresheen.dashboard.security_headers import SecurityHeadersMiddleware
from kresheen.dashboard.workers import check_worker_count
from kresheen.engine.llm.provider import AnthropicProvider
from kresheen.engine.llm.types import LlmProvider
from kresheen.engine.run_safety import RunGate, reconcile_stale_runs
from kresheen.plugins import PluginRegistry, load_plugins, set_registry
from kresheen.secrets.store import SecretKeyMissing
from kresheen.storage.sql_repo import SQLRepository

logger = logging.getLogger(__name__)

# repo_root/frontend/dist -- three parents up from this file's directory
# (dashboard -> kresheen -> src -> repo root). Overridable via the
# `frontend_dist` param (and `kresheen serve --frontend-dist` /
# `KRESHEEN_FRONTEND_DIST`) so a Docker image that copies the built SPA
# to a different path doesn't need this file changed.
_DEFAULT_FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"
# A release wheel carries the built SPA inside the package (kresheen/web), so `pip install kresheen` serves the UI
# without a repository checkout. Used when the repo-relative build is absent.
_PACKAGED_FRONTEND_DIST = Path(__file__).resolve().parents[1] / "web"


def _default_frontend_dist() -> Path:
    return _DEFAULT_FRONTEND_DIST if _DEFAULT_FRONTEND_DIST.is_dir() else _PACKAGED_FRONTEND_DIST


def create_app(
    db_url: str = "sqlite:///kresheen.db",
    frontend_dist: Path | str | None = None,
    plugins: PluginRegistry | None = None,
    llm_provider: LlmProvider | None = None,
) -> FastAPI:
    # The interactive docs and the schema are off unless KRESHEEN_API_DOCS=1 (a route map is a free recon aid).
    check_worker_count()  # several workers weaken the in-memory login throttle: refuse unless the operator opts in
    docs_on = os.environ.get("KRESHEEN_API_DOCS", "").strip().lower() in ("1", "true", "yes")
    app = FastAPI(
        title="Kresheen Dashboard",
        docs_url="/docs" if docs_on else None,
        redoc_url="/redoc" if docs_on else None,
        openapi_url="/openapi.json" if docs_on else None,
    )
    registry = plugins if plugins is not None else load_plugins()
    set_registry(registry)  # before the repository, so each plugin's storage hook runs when the schema is created
    app.state.repo = SQLRepository(db_url)
    app.state.plugins = registry
    # The SDK is imported lazily inside the provider, so this costs nothing while AI is off.
    app.state.llm_provider = llm_provider if llm_provider is not None else AnthropicProvider()

    @app.exception_handler(RequestValidationError)
    async def _invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default body echoes each error's `input`: a multi-megabyte upload came straight back, and an
        # unpaired surrogate in it made the 422 itself crash with a 500. Keep location, message and type only.
        errors = [
            {
                "loc": [part if isinstance(part, int) else str(part) for part in error.get("loc", ())],
                "msg": str(error.get("msg", "")).encode("utf-8", "replace").decode("utf-8")[:300],
                "type": str(error.get("type", "")),
            }
            for error in exc.errors()[:50]
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(SecretKeyMissing)
    async def _secret_key_missing(request: Request, exc: SecretKeyMissing) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"detail": "Storing secrets needs KRESHEEN_SECRET_KEY to be set on the server."},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Without this a failure is a bare text 500 and the keep-alive connection is dropped. The detail stays
        # in the server log; the client gets a short JSON body and no internals.
        logging.getLogger(__name__).exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    app.state.login_throttle = LoginThrottle()
    app.state.run_gate = RunGate()
    try:  # a run left non-terminal by a crash or kill would otherwise show "in progress" forever
        reconcile_stale_runs(app.state.repo)
    except Exception:
        logging.getLogger(__name__).exception("Could not reconcile stale runs at startup")
    app.add_middleware(AuditMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)  # refuse an oversized body before anything reads it
    app.add_middleware(SecurityHeadersMiddleware)  # outermost: every response, including refusals, carries the headers

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        # Liveness/readiness probe for the container, Helm and compose. Unauthenticated on purpose and says nothing
        # about versions, paths or the database.
        return {"status": "ok"}

    app.include_router(api_auth.router)
    app.include_router(api_capabilities.router)
    app.include_router(api_report.router)
    # Threat-modeling platform (primary product going forward):
    app.include_router(api_users.router)
    app.include_router(api_tokens.router)
    app.include_router(api_audit.router)
    app.include_router(api_applications.router)
    app.include_router(api_intake.router)
    app.include_router(api_groups.router)
    app.include_router(api_dashboard.router)
    app.include_router(api_threat_kb.router)
    app.include_router(api_threats.router)
    app.include_router(api_threat_explain.router)
    app.include_router(api_settings_ai.router)
    app.include_router(api_agent_config.router)  # every route answers 404 until the owner enables AI
    registry.mount_routers(app)

    # Every method: an unknown `/api/*` path is a JSON 404 whether or not the SPA catch-all below exists, never
    # a 405 that hints the path is served for some other method.
    @app.api_route(
        "/api/{rest:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False
    )
    def api_not_found(rest: str) -> None:
        raise HTTPException(status_code=404, detail="Not found")

    # Registered last: `/api/*` routes above always match first, so this
    # catch-all only ever serves the SPA shell for browser navigation.
    # Guarded on the dist dir actually existing so `TestClient(create_app())`
    # in tests (which never run `npm run build`) doesn't fail at startup --
    # the API is fully testable without a frontend build.
    dist = Path(frontend_dist) if frontend_dist is not None else _default_frontend_dist()
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=str(dist / "assets")), name="frontend-assets")
        index_path = dist / "index.html"

        @app.get("/{full_path:path}")
        def spa(full_path: str) -> FileResponse:
            # A mistyped API path must be a JSON 404, not the HTML app shell with a 200.
            if full_path == "api" or full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(index_path)
    else:
        logger.warning(
            "Frontend build not found at %s -- the API will work but the SPA won't "
            "be served. Run `npm run build` in frontend/ first.",
            dist,
        )

    return app
