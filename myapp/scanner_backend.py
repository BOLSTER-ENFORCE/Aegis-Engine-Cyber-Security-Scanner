import os
import sys
import ctypes
import platform
import subprocess
import time
import socket
import hashlib
import json
import re
from datetime import datetime, timedelta
import psutil

# ======================================================================
# ⚙️ AEGIS SCANNING ENGINE - BACKEND UTILITIES
# ======================================================================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def get_uptime():
    try:
        boot_time_timestamp = psutil.boot_time()
        uptime_seconds = time.time() - boot_time_timestamp
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)    
        uptime_str = ""
        if days > 0: uptime_str += f"{int(days)}d "
        if hours > 0: uptime_str += f"{int(hours)}h "
        uptime_str += f"{int(minutes)}m"
        return uptime_str
    except Exception:
        return "Unknown"

def get_external_ip():
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=3) as response:
            data = json.loads(response.read().decode())
            return data.get("ip", "Offline")
    except Exception:
        return "Offline / Unavailable"

def profile_system_details():
    details = {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "os_arch": platform.machine(),
        "cpu_model": platform.processor() or "Unknown CPU",
        "cpu_physical_cores": psutil.cpu_count(logical=False) or 0,
        "cpu_logical_cores": psutil.cpu_count(logical=True) or 0,
        "cpu_usage_pct": psutil.cpu_percent(interval=0.1),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "ram_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
        "ram_used_pct": psutil.virtual_memory().percent,
        "uptime": get_uptime(),
        "external_ip": get_external_ip(),
        "disks": [],
        "network_adapters": []
    }
    try:
        for part in psutil.disk_partitions(all=False):
            if os.name == 'nt' and 'cdrom' in part.opts:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                details["disks"].append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "used_pct": usage.percent
                })
            except (PermissionError, FileNotFoundError):
                continue
    except Exception:
        pass
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for interface, addr_list in addrs.items():
            is_up = stats[interface].isup if interface in stats else False
            ip_address = "No IP"
            mac_address = "No MAC"
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip_address = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac_address = addr.address
            if ip_address != "No IP" or is_up:
                details["network_adapters"].append({
                    "interface": interface,
                    "status": "UP" if is_up else "DOWN",
                    "ip": ip_address,
                    "mac": mac_address
                })
    except Exception:
        pass
    return details

def run_powershell_cmd(cmd, timeout=4):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, check=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

# --- Extended Hardware Specs ---
def get_extended_hardware_specs():
    """Retrieve detailed hardware stats: GPU, Battery, motherboard, BIOS, memory, IO."""
    import psutil
    specs = {
        "battery": {},
        "gpu": [],
        "motherboard": {},
        "bios": {},
        "cpu_freq": {},
        "cpu_per_core": [],
        "swap_memory": {},
        "disk_io": {},
        "net_io": {}
    }

    # Battery
    try:
        battery = psutil.sensors_battery()
        if battery:
            specs["battery"] = {
                "percent": battery.percent,
                "power_plugged": battery.power_plugged,
                "secsleft": battery.secsleft
            }
    except Exception:
        pass

    # CPU frequency and per-core usage
    try:
        freq = psutil.cpu_freq()
        if freq:
            specs["cpu_freq"] = {
                "current": round(freq.current, 2),
                "min": round(freq.min, 2),
                "max": round(freq.max, 2)
            }
        specs["cpu_per_core"] = psutil.cpu_percent(percpu=True)
    except Exception:
        pass

    # Swap memory
    try:
        swap = psutil.swap_memory()
        specs["swap_memory"] = {
            "total_gb": round(swap.total / (1024**3), 2),
            "used_gb": round(swap.used / (1024**3), 2),
            "free_gb": round(swap.free / (1024**3), 2),
            "used_pct": swap.percent
        }
    except Exception:
        pass

    # Disk IO
    try:
        disk_io = psutil.disk_io_counters()
        if disk_io:
            specs["disk_io"] = {
                "read_mb": round(disk_io.read_bytes / (1024**2), 2),
                "write_mb": round(disk_io.write_bytes / (1024**2), 2)
            }
    except Exception:
        pass

    # Network IO
    try:
        net_io = psutil.net_io_counters()
        if net_io:
            specs["net_io"] = {
                "sent_mb": round(net_io.bytes_sent / (1024**2), 2),
                "recv_mb": round(net_io.bytes_recv / (1024**2), 2)
            }
    except Exception:
        pass

    # GPU, Motherboard, BIOS (Windows only)
    if platform.system() == "Windows":
        try:
            gpu_data = run_powershell_cmd("Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM | ConvertTo-Json")
            if gpu_data:
                parsed = json.loads(gpu_data)
                gpus = parsed if isinstance(parsed, list) else [parsed]
                for g in gpus:
                    specs["gpu"].append({
                        "name": g.get("Name", "Unknown GPU"),
                        "vram_gb": round(g.get("AdapterRAM", 0) / (1024**3), 2) if g.get("AdapterRAM") else "Unknown"
                    })
        except Exception:
            pass

        try:
            mb_data = run_powershell_cmd("Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product | ConvertTo-Json")
            if mb_data:
                parsed = json.loads(mb_data)
                specs["motherboard"] = {
                    "manufacturer": parsed.get("Manufacturer", "Unknown"),
                    "product": parsed.get("Product", "Unknown")
                }
        except Exception:
            pass

        try:
            bios_data = run_powershell_cmd("Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version | ConvertTo-Json")
            if bios_data:
                parsed = json.loads(bios_data)
                specs["bios"] = {
                    "manufacturer": parsed.get("Manufacturer", "Unknown"),
                    "name": parsed.get("Name", "Unknown"),
                    "version": parsed.get("Version", "Unknown")
                }
        except Exception:
            pass

    return specs
