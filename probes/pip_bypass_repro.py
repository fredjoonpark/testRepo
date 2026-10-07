"""
Minimal repro: a Processing Engine plugin installs and imports a PyPI package
even though package management is disabled on the cluster.

Installs into a private /tmp dir only (shared venv untouched) and cleans up.
"""
import importlib
import importlib.metadata
import importlib.util
import os
import shutil
import subprocess
import sys

TARGET = "/tmp/pip_bypass_repro"
PACKAGE, MODULE = "cowsay==6.1", "cowsay"  # pure-Python, no deps, not pre-installed


def process_request(influxdb3_local, query_parameters, request_headers, request_body, args=None):
    # sys.executable is the embedded server binary, so use the venv's interpreter.
    python = os.path.join(sys.prefix, "bin", "python3")
    shutil.rmtree(TARGET, ignore_errors=True)
    # Prove the package is not already available before we install it.
    result = {"python": python, "available_before_install": importlib.util.find_spec(MODULE) is not None}
    try:
        r = subprocess.run(
            [python, "-m", "pip", "install", "--target", TARGET, "--no-deps", "--no-cache-dir",
             "--disable-pip-version-check", PACKAGE],
            capture_output=True, text=True, timeout=120,
        )
        result.update(pip_rc=r.returncode, pip_output=(r.stdout + r.stderr).strip()[-600:])
        if r.returncode == 0:
            sys.path.insert(0, TARGET)
            try:
                mod = importlib.import_module(MODULE)
                result["imported_from"] = mod.__file__
                result["installed_version"] = importlib.metadata.version("cowsay")
                # Execute code from the installed package, not just import it.
                output = mod.get_output_string("cow", "pip bypass")
                result["usage_output"] = output
                result["usage_ok"] = "pip bypass" in output
                result["bypass"] = (
                    not result["available_before_install"]
                    and mod.__file__.startswith(TARGET)
                    and result["usage_ok"]
                )
            finally:
                sys.path.remove(TARGET)
                for name in [m for m in sys.modules if m == MODULE or m.startswith(MODULE + ".")]:
                    sys.modules.pop(name, None)
        else:
            result["bypass"] = False
        return result
    finally:
        shutil.rmtree(TARGET, ignore_errors=True)
