"""
src/dashboard/app.py - Dashboard Web Application and Static Mounting.
"""

from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["Dashboard"])
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


@router.get("/dashboard", include_in_schema=False)
def get_dashboard():
    """Serve the primary responsive HTML dashboard."""
    index_path = TEMPLATES_DIR / "index.html"
    if not index_path.exists():
        index_path = STATIC_DIR / "index.html"
    return FileResponse(str(index_path))
