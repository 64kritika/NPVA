import subprocess

def run_nmap_xml(target: str) -> str:
    """
    Runs nmap service/version detection and returns XML output as a string.
    Uses -oX - to write XML to stdout.
    """
    cmd = ["nmap", "-sV", "-T4", "-oX", "-", target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
    except FileNotFoundError:
        raise RuntimeError("nmap not found. Install it with: sudo apt install nmap")

    if proc.returncode != 0:
        err = proc.stderr.strip() or "Unknown nmap error"
        raise RuntimeError(f"Nmap failed: {err}")

    return proc.stdout
