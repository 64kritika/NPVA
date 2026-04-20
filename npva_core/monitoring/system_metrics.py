import os
import platform
import shutil
import subprocess


def _read_proc_uptime():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            seconds = float(f.read().split()[0])
            return int(seconds)
    except Exception:
        return None


def _format_uptime(seconds):
    if seconds is None:
        return "N/A"

    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


def _get_cpu_usage():
    """
    Lightweight CPU usage using top output.
    """
    try:
        result = subprocess.check_output(
            "top -bn1 | grep 'Cpu(s)'",
            shell=True,
            text=True,
        )
        # Example contains idle %, so cpu_used = 100 - idle
        parts = result.split(",")
        idle_part = None
        for p in parts:
            if "id" in p:
                idle_part = p.strip()
                break

        if idle_part:
            idle_value = float(idle_part.split()[0])
            used = round(100.0 - idle_value, 1)
            return used
    except Exception:
        pass

    return "N/A"


def get_system_metrics():
    """
    Return simple host/device health metrics for dashboard.
    """
    hostname = platform.node()

    # Memory
    try:
        mem = shutil.os.sysconf("SC_PAGE_SIZE") * shutil.os.sysconf("SC_PHYS_PAGES")
        avail = shutil.os.sysconf("SC_PAGE_SIZE") * shutil.os.sysconf("SC_AVPHYS_PAGES")
        used_mem = mem - avail
        mem_total_gb = round(mem / (1024 ** 3), 2)
        mem_used_gb = round(used_mem / (1024 ** 3), 2)
        mem_percent = round((used_mem / mem) * 100, 1) if mem > 0 else 0
    except Exception:
        mem_total_gb = "N/A"
        mem_used_gb = "N/A"
        mem_percent = "N/A"

    # Disk
    try:
        disk = shutil.disk_usage("/")
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
        disk_percent = round((disk.used / disk.total) * 100, 1) if disk.total > 0 else 0
    except Exception:
        disk_total_gb = "N/A"
        disk_used_gb = "N/A"
        disk_percent = "N/A"

    uptime_seconds = _read_proc_uptime()

    return {
        "hostname": hostname or "N/A",
        "cpu_percent": _get_cpu_usage(),
        "memory_percent": mem_percent,
        "memory_used_gb": mem_used_gb,
        "memory_total_gb": mem_total_gb,
        "disk_percent": disk_percent,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "uptime": _format_uptime(uptime_seconds),
    }
