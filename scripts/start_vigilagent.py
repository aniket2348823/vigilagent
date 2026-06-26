"""
Cross-platform launcher for Vigilagent.
Works on Windows, Linux, and macOS without modification.
Replaces the Windows-only start_vulagent.bat.
"""

import subprocess
import sys
import os
import platform
import time


def main():
    is_windows = platform.system() == "Windows"
    root = os.path.dirname(os.path.abspath(__file__))

    print("=" * 50)
    print("  VIGILAGENT — Cross-Platform Launcher")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print(f"  Python: {sys.version.split()[0]}")
    print("=" * 50)

    # Start backend
    backend_cmd = [sys.executable, "-m", "backend.main", "--mode", "serve"]
    creation_flags = subprocess.CREATE_NEW_CONSOLE if is_windows else 0
    
    try:
        backend = subprocess.Popen(
            backend_cmd,
            cwd=root,
            creationflags=creation_flags
        )
        print(f"[OK] Backend started (PID {backend.pid})")
    except Exception as e:
        print(f"[ERROR] Backend failed to start: {e}")
        sys.exit(1)

    time.sleep(2)

    # Start frontend
    npm_cmd = "npm.cmd" if is_windows else "npm"
    local_node_dir = os.path.join(root, ".node", "node-v20.12.2-win-x64")
    local_npm = os.path.join(local_node_dir, "npm.cmd")
    
    env = os.environ.copy()
    if os.path.exists(local_npm):
        npm_cmd = local_npm
        env["PATH"] = local_node_dir + os.pathsep + env.get("PATH", "")
        
    try:
        frontend = subprocess.Popen(
            [npm_cmd, "run", "dev"],
            cwd=root,
            env=env,
            creationflags=creation_flags
        )
        print(f"[OK] Frontend started (PID {frontend.pid})")
    except Exception as e:
        print(f"[ERROR] Frontend failed to start: {e}")
        backend.terminate()
        sys.exit(1)

    print()
    print("[INFO] Vigilagent running at http://localhost:5173")
    print("   Backend API at http://localhost:8000")
    print("   Press Ctrl+C to stop all services.")
    print()

    try:
        backend.wait()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down Vigilagent...")
        backend.terminate()
        frontend.terminate()
        try:
            backend.wait(timeout=5)
            frontend.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend.kill()
            frontend.kill()
        print("[OK] Vigilagent stopped.")


if __name__ == "__main__":
    main()
