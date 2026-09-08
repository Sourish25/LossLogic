"""
src/api/app.py - Master FastAPI Application Setup for CyberRiskQuant.
"""

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.api.routes import router as api_router

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "dashboard" / "static"
TEMPLATES_DIR = BASE_DIR / "dashboard" / "templates"


def create_app() -> FastAPI:
    """Create and configure the primary FastAPI application."""
    app = FastAPI(
        title="CyberRiskQuant Platform",
        version="1.0.0",
        description="AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Enable CORS for local dashboards and cross-origin tools
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount REST API router
    app.include_router(api_router)

    # Mount static assets if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Serve dashboard index on root path
    @app.get("/", include_in_schema=False)
    def serve_dashboard():
        index_file = TEMPLATES_DIR / "index.html"
        if not index_file.exists():
            index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {
            "platform": "CyberRiskQuant",
            "status": "ready",
            "api_docs": "/docs",
            "api_health": "/api/v1/health",
        }

    return app


app = create_app()
