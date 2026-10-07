"""
Read-only environment probe for the InfluxDB 3 Processing Engine (request trigger).

Answers: could a plugin install/load third-party packages without the install API?
Checks package-manager availability, process identity, writable locations (and
noexec mounts), subprocess spawning, and outbound network reachability.

Installs nothing. By default writability is checked with os.access only. Pass
?write_test=1 to instead create and immediately delete an empty temp file in each
candidate directory (more accurate on read-only/overlay mounts).

Output contains no environment variable values, only names.
"""
import importlib.util
import os
import shutil
import site
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

EGRESS_TARGETS = {
    "pypi_simple": "https://pypi.org/simple/",
    "pypi_files": "https://files.pythonhosted.org/",
    "pytorch_index": "https://download.pytorch.org/whl/",
    "github_raw": "https://raw.githubusercontent.com/",
    "generic_internet": "https://example.com/",
}
# Hosts from which a plugin could fetch a wheel. github_raw counts: a wheel can be
# committed to any repo the plugin host can read.
WHEEL_SOURCES = ("pypi_files", "pytorch_index", "github_raw", "generic_internet")
TIMEOUT_S = 4
ENV_NAME_PREFIXES = ("PIP_", "UV_", "PYTHON", "VIRTUAL_ENV", "CONDA")
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")


def _identity():
    info = {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "is_root": os.geteuid() == 0}
    try:
        import pwd

        info["user"] = pwd.getpwuid(os.geteuid()).pw_name
    except Exception as e:
        info["user"] = f"unknown ({e.__class__.__name__})"
    return info


def _python():
    return {
        "executable": sys.executable,
        "version": sys.version.split()[0],
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "in_venv": sys.prefix != sys.base_prefix,
        "sys_path": sys.path,
    }


def _env_names():
    return {
        "relevant_env_var_names": sorted(k for k in os.environ if k.startswith(ENV_NAME_PREFIXES)),
        "proxy_vars_set": sorted(k for k in PROXY_VARS if k in os.environ),
    }


def _package_managers():
    out = {
        "pip_module_importable": importlib.util.find_spec("pip") is not None,
        "ensurepip_importable": importlib.util.find_spec("ensurepip") is not None,
        "binaries_on_path": {b: shutil.which(b) for b in ("pip", "pip3", "uv", "python3", "python")},
        "pip_conf_files": [
            p
            for p in (
                "/etc/pip.conf",
                os.path.expanduser("~/.pip/pip.conf"),
                os.path.expanduser("~/.config/pip/pip.conf"),
                os.path.join(sys.prefix, "pip.conf"),
            )
            if os.path.exists(p)
        ],
    }
    bindir = os.path.join(sys.prefix, "bin")
    out["prefix_bin_listing"] = sorted(os.listdir(bindir)) if os.path.isdir(bindir) else None
    return out


def _candidate_pythons():
    # The interpreter is embedded in the server, so sys.executable may be the
    # influxdb3 binary itself. Only run things that are clearly a Python binary.
    cands = []
    if sys.executable and "python" in os.path.basename(sys.executable).lower():
        cands.append(sys.executable)
    for p in (
        os.path.join(sys.prefix, "bin", "python3"),
        os.path.join(sys.prefix, "bin", "python"),
        shutil.which("python3"),
        shutil.which("python"),
    ):
        if p and os.path.isfile(p) and p not in cands:
            cands.append(p)
    return cands


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"cmd": cmd, "rc": r.returncode, "out": (r.stdout or r.stderr).strip()[:300]}
    except Exception as e:
        return {"cmd": cmd, "error": f"{e.__class__.__name__}: {e}"}


def _subprocess_checks():
    runs = []
    for py in _candidate_pythons():
        runs.append(_run([py, "--version"]))
        runs.append(_run([py, "-m", "pip", "--version"]))
    for b in ("pip", "pip3", "uv"):
        path = shutil.which(b)
        if path:
            runs.append(_run([path, "--version"]))
    return {"candidate_pythons": _candidate_pythons(), "runs": runs}


def _mount_opts(path):
    # Longest mount-point prefix match from /proc/mounts (Linux only).
    try:
        real = os.path.realpath(path)
        best, opts = "", None
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and (real == parts[1] or real.startswith(parts[1].rstrip("/") + "/")):
                    if len(parts[1]) > len(best):
                        best, opts = parts[1], parts[3].split(",")
        return {"mount_point": best, "ro": "ro" in (opts or []), "noexec": "noexec" in (opts or [])}
    except Exception as e:
        return {"error": f"{e.__class__.__name__}: {e}"}


def _writable(write_test):
    dirs = {
        "tempdir": tempfile.gettempdir(),
        "cwd": os.getcwd(),
        "home": os.path.expanduser("~"),
        "sys_prefix": sys.prefix,
        "purelib": sysconfig.get_paths().get("purelib"),
    }
    try:
        for i, p in enumerate(site.getsitepackages()):
            dirs[f"site_packages_{i}"] = p
    except Exception:
        pass
    if site.ENABLE_USER_SITE:
        dirs["user_site"] = site.getusersitepackages()

    out = {}
    for name, d in dirs.items():
        entry = {"path": d, "exists": bool(d) and os.path.isdir(d)}
        if entry["exists"]:
            entry["os_access_w"] = os.access(d, os.W_OK)
            entry["mount"] = _mount_opts(d)
            if write_test:
                try:
                    with tempfile.NamedTemporaryFile(dir=d, prefix=".env_probe_", delete=True):
                        pass
                    entry["write_test"] = "ok"
                except Exception as e:
                    entry["write_test"] = f"{e.__class__.__name__}: {e}"
        out[name] = entry
    return out


def _egress():
    out = {}
    for name, url in EGRESS_TARGETS.items():
        entry = {"url": url}
        t0 = time.monotonic()
        try:
            socket.getaddrinfo(urllib.parse.urlparse(url).hostname, 443)
            entry["dns"] = "ok"
        except Exception as e:
            entry["dns"] = f"{e.__class__.__name__}: {e}"
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "influxdb3-env-probe"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                entry["http"] = resp.status
        except urllib.error.HTTPError as e:
            entry["http"] = e.code  # any HTTP response means the host is reachable
        except Exception as e:
            entry["http"] = f"{e.__class__.__name__}: {e}"
        entry["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        out[name] = entry
    return out


def _is_writable(v):
    if not isinstance(v, dict) or not v.get("exists"):
        return False
    if "write_test" in v:
        return v["write_test"] == "ok"
    return bool(v.get("os_access_w"))


def _summarize(r):
    pm = r.get("package_managers", {})
    runs = r.get("subprocess", {}).get("runs", [])
    pip_runs = any(x.get("rc") == 0 and "pip" in x.get("cmd", []) for x in runs)
    writable = r.get("writable", {})
    writable_dirs = sorted(k for k, v in writable.items() if _is_writable(v))
    writable_exec_dirs = sorted(k for k in writable_dirs if not writable[k].get("mount", {}).get("noexec"))
    reachable = sorted(k for k, v in r.get("egress", {}).items() if isinstance(v.get("http"), int))
    wheel_source = [h for h in WHEEL_SOURCES if h in reachable]
    return {
        "pip_importable": bool(pm.get("pip_module_importable")),
        "pip_runs_via_subprocess": pip_runs,
        "uv_on_path": bool(pm.get("binaries_on_path", {}).get("uv")),
        "site_packages_writable": any(k.startswith(("site_packages", "purelib")) for k in writable_dirs),
        "writable_dirs": writable_dirs,
        "writable_exec_dirs": writable_exec_dirs,
        "reachable_hosts": reachable,
        # pure-Python wheel: download + unzip into a writable dir + sys.path.insert
        "pure_python_bypass_possible": bool(writable_dirs) and bool(wheel_source),
        # compiled wheel (.so) additionally needs a writable dir that is not noexec
        "compiled_bypass_possible": bool(writable_exec_dirs) and bool(wheel_source),
        "pip_install_bypass_possible": pip_runs and bool(writable_dirs) and bool(
            {"pypi_simple", "pypi_files"} <= set(reachable) or r.get("env", {}).get("proxy_vars_set")
        ),
    }


def process_request(influxdb3_local, query_parameters, request_headers, request_body, args=None):
    write_test = str((query_parameters or {}).get("write_test", "0")).lower() in ("1", "true", "yes")
    report = {"write_test_enabled": write_test}
    for section, fn in (
        ("identity", _identity),
        ("python", _python),
        ("env", _env_names),
        ("package_managers", _package_managers),
        ("subprocess", _subprocess_checks),
        ("writable", lambda: _writable(write_test)),
        ("egress", _egress),
    ):
        try:
            report[section] = fn()
        except Exception as e:
            report[section] = {"error": f"{e.__class__.__name__}: {e}"}
    report["summary"] = _summarize(report)
    influxdb3_local.info(f"env_probe summary: {report['summary']}")
    return report
