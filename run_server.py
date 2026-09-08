import os
import sys
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 70)
    print(" LossLogic — Actuarial Cyber Risk & Capital Allocation Platform")
    print("=" * 70)
    print(f" Dashboard URL: http://{host}:{port}/")
    print(f" API Docs (Swagger): http://{host}:{port}/docs")
    print(f" API Health Probe: http://{host}:{port}/api/v1/health")
    print("=" * 70)
    uvicorn.run("src.api.app:app", host=host, port=port, reload=False)
