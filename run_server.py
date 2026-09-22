import os
import sys
import socket
import threading
import time
import webbrowser
import uvicorn


def get_local_ip() -> str:
    """Detect LAN / Wi-Fi IP for multi-device enterprise demonstrations."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def free_port_if_occupied(port: int) -> None:
    """Gracefully terminate any stale process holding the target port on Windows."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return  # Port is already free
        
        if sys.platform == "win32":
            import subprocess
            cmd = f'netstat -ano | findstr :{port}'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            for line in proc.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and "LISTENING" in parts:
                    pid = int(parts[-1])
                    if pid != os.getpid() and pid > 0:
                        print(f"[*] Port {port} is occupied by stale PID {pid}. Freeing port...")
                        subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                        time.sleep(1)
    except Exception as e:
        print(f"[*] Port check notice: {e}")


def auto_open_browser(url: str, delay: float = 1.2) -> None:
    """Open default browser (e.g. Chrome) automatically after server initialization."""
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    t = threading.Thread(target=_open, daemon=True)
    t.start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    bind_host = os.environ.get("HOST", "0.0.0.0")
    local_ip = get_local_ip()

    # Free port 8000 if occupied by previous run
    free_port_if_occupied(port)

    browser_url = f"http://localhost:{port}/"
    wifi_url = f"http://{local_ip}:{port}/"

    print("=" * 72)
    print("  LossLogic — Actuarial Cyber Risk & Capital Allocation Platform")
    print("=" * 72)
    print(f"  Chrome / Browser:       {browser_url}")
    print(f"  Local Loopback:         http://127.0.0.1:{port}/")
    print(f"  Executive / 2nd Laptop Wi-Fi: {wifi_url}")
    print(f"  API Docs (Swagger):     http://localhost:{port}/docs")
    print(f"  API Health Probe:       http://localhost:{port}/api/v1/health")
    # Launch browser automatically only in desktop environments (skip on Render/cloud)
    if not os.environ.get("RENDER") and not os.environ.get("CI"):
        print("  Launching Chrome browser automatically...")
        auto_open_browser(browser_url)
    print("=" * 72)

    # Start FastAPI server
    uvicorn.run("src.api.app:app", host=bind_host, port=port, reload=False)

