"""
Read-only host-access probe for an InfluxDB 3 Processing Engine request trigger.

Checks IMDSv1/v2, environment names, readable files in /etc and /opt/amazon,
/proc/*/environ, listening sockets, setuid/setgid files, sudo policy, Linux
capabilities, container runtime sockets, and selected internal TCP endpoints.

No packages are installed, privilege escalation attempted, or credentials used.
Credential bodies are inspected in memory; environment values, file contents,
metadata tokens, and credential values are never returned or logged.

Query parameters override trigger args:
  targets=10.0.1.10:443,10.0.2.20:8080,[fd00::10]:443
  timeout_s=1       per network operation, maximum 3 seconds
  budget_s=30       shared time budget, maximum 60 seconds
  max_files=1000    entries examined per filesystem root, maximum 10000
  max_pids=128      process environments examined, maximum 1024
  skip_imds=1 / skip_network=1 / skip_sudo=1

Targets must be literal IP:port pairs; CIDRs and hostname scans are unsupported.
By default, TCP checks include private DNS resolvers on port 53 and IPv4 default
gateways on port 443. A failed TCP connection does not prove a host is unreachable.
Limits, permission failures, and unavailable Linux interfaces appear in output.
"""

import errno
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque


FILE_ROOTS = ("/etc", "/opt/amazon")
BINARY_ROOTS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/usr/local/sbin", "/opt/amazon",
)
IMDS_BASES = ("http://169.254.169.254", "http://[fd00:ec2::254]")
MAX_TARGETS = 16
READ_LIMIT = 65536
SECRET_NAME = re.compile(
    r"SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|ACCESS_KEY|API_KEY|PRIVATE_KEY|AUTH",
    re.IGNORECASE,
)
SENSITIVE_PATH = re.compile(
    r"(^|/)(shadow|gshadow|\.env(?:\..*)?|credentials|secrets?)(/|$)"
    r"|(?:password|passwd|token|credential|secret|private|id_rsa|id_ed25519)"
    r"|(?:\.pem|\.key|\.p12|\.pfx|\.kdbx)$",
    re.IGNORECASE,
)
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}\Z")
ROLE_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}\Z")
CAP_NAMES = (
    "CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP "
    "LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK "
    "IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN "
    "SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE "
    "AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG "
    "WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE"
).split()
DANGEROUS_CAPS = {
    "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID",
    "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
    "CAP_SETFCAP",
}


def _error(exc):
    # Exception messages can contain response bodies, environment values, or URLs.
    result = {"error": type(exc).__name__}
    if isinstance(getattr(exc, "errno", None), int):
        result["errno"] = exc.errno
    return result


def _number(value, default, minimum, maximum, integer=False):
    try:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError()
        return int(max(minimum, min(maximum, number))) if integer else max(
            minimum, min(maximum, number)
        )
    except (ValueError, TypeError, OverflowError):
        return default


def _options(query, args):
    values = dict(args) if isinstance(args, dict) else {}
    values.update(query or {})
    out = {
        "timeout_s": _number(values.get("timeout_s"), 1.0, 0.1, 3.0),
        "budget_s": _number(values.get("budget_s"), 30.0, 1.0, 60.0),
        "max_files": _number(values.get("max_files"), 1000, 1, 10000, True),
        "max_pids": _number(values.get("max_pids"), 128, 1, 1024, True),
        "targets": values.get("targets", ""),
    }
    for key in ("skip_imds", "skip_network", "skip_sudo"):
        out[key] = str(values.get(key, "0")).lower() in ("1", "true", "yes")
    return out


class _Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def timeout(self, requested):
        left = self.remaining()
        if not left:
            raise TimeoutError()
        return min(requested, left)


def _read_bytes(path, limit=READ_LIMIT):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        return data[:limit], len(data) > limit
    finally:
        os.close(fd)


def _text(path):
    data, truncated = _read_bytes(path)
    return data.decode("utf-8", "replace"), truncated


def _identity():
    out = {
        "pid": os.getpid(), "uid": os.getuid(), "euid": os.geteuid(),
        "gid": os.getgid(), "egid": os.getegid(), "groups": os.getgroups(),
        "is_root": os.geteuid() == 0,
    }
    try:
        import pwd
        out["user"] = pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError):
        out["user"] = None
    return out


def _env_summary(items):
    # Reject malformed names instead of accidentally echoing a malformed value.
    names = sorted({str(name) for name in items if ENV_NAME.fullmatch(str(name))})
    return {
        "names": names,
        "nonempty_credential_like_names": [
            name for name in names if SECRET_NAME.search(name) and items[name]
        ],
        "aws_key_pair_present": bool(
            items.get("AWS_ACCESS_KEY_ID") and items.get("AWS_SECRET_ACCESS_KEY")
        ),
        "values_redacted": True,
    }


def _process_environments(opts, budget):
    out = {"processes": [], "denied": 0, "vanished": 0, "errors": [], "truncated": False}
    try:
        pids = sorted(
            (name for name in os.listdir("/proc") if name.isdigit()), key=int
        )
    except OSError as exc:
        out.update(_error(exc))
        return out
    # Inspect this plugin and its server/parent before other processes.
    priority = [str(os.getpid()), str(os.getppid()), "1"]
    pids = list(dict.fromkeys(priority + pids))
    out["visible_pid_count"] = len(pids)
    for index, pid in enumerate(pids):
        if index >= opts["max_pids"] or not budget.remaining():
            out["truncated"] = True
            break
        path = "/proc/" + pid + "/environ"
        try:
            data, truncated = _read_bytes(path)
            # If capped, discard the last possibly incomplete environment entry.
            chunks = data.split(b"\0")
            if truncated:
                chunks = chunks[:-1]
            items = {}
            for chunk in chunks:
                name, sep, value = chunk.partition(b"=")
                if sep:
                    items[name.decode("utf-8", "replace")] = bool(value)
            row = {"pid": int(pid), "path": path, "readable": True,
                   "content_truncated": truncated, **_env_summary(items)}
            out["processes"].append(row)
        except PermissionError:
            out["denied"] += 1
        except FileNotFoundError:
            out["vanished"] += 1
        except (OSError, ValueError) as exc:
            if len(out["errors"]) < 10:
                out["errors"].append({"pid": int(pid), **_error(exc)})
    return out


def _walk(root, limit, budget, coverage):
    """Bounded breadth-first walk; directory symlinks are not traversed."""
    pending = deque([root])
    coverage.update(entries_examined=0, errors=0, symlink_dirs_skipped=0, truncated=False)
    while pending:
        if not budget.remaining():
            coverage["truncated"] = True
            return
        directory = pending.popleft()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if coverage["entries_examined"] >= limit or not budget.remaining():
                        coverage["truncated"] = True
                        return
                    coverage["entries_examined"] += 1
                    try:
                        info = entry.stat(follow_symlinks=True)
                        if stat.S_ISDIR(info.st_mode):
                            if entry.is_symlink():
                                coverage["symlink_dirs_skipped"] += 1
                            else:
                                pending.append(entry.path)
                        elif stat.S_ISREG(info.st_mode):
                            yield entry.path, info
                    except OSError:
                        coverage["errors"] += 1
        except OSError as exc:
            coverage["errors"] += 1
            if directory == root:
                coverage.update(_error(exc))


def _file_info(path, info):
    return {
        "path": path, "mode": oct(stat.S_IMODE(info.st_mode)),
        "uid": info.st_uid, "gid": info.st_gid,
    }


def _readable_files(opts, budget):
    out = {"roots": {}, "contents_redacted": True}
    for root in FILE_ROOTS:
        coverage = {"readable_files": [], "unreadable_files": 0}
        for path, info in _walk(root, opts["max_files"], budget, coverage):
            try:
                # Read one byte to verify access, rather than trusting mode bits.
                _read_bytes(path, 0)
                coverage["readable_files"].append({
                    **_file_info(path, info),
                    "sensitive_name": bool(SENSITIVE_PATH.search(path)),
                    "symlink": os.path.islink(path),
                })
            except (OSError, ValueError):
                coverage["unreadable_files"] += 1
        out["roots"][root] = coverage
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http(opener, url, opts, budget, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=budget.timeout(opts["timeout_s"])) as response:
            body = response.read(16385)
            return {"status": response.status, "truncated": len(body) > 16384}, body[:16384]
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        return {"status": status}, b""
    except Exception as exc:
        return _error(exc), b""


def _credential_summary(meta, body):
    out = {**meta, "credentials_present": False}
    if meta.get("status") != 200 or meta.get("truncated"):
        return out
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError()
        fields = ("AccessKeyId", "SecretAccessKey", "Token")
        out["present_fields"] = [
            name for name in fields if isinstance(data.get(name), str) and data[name]
        ]
        out["credentials_present"] = (
            len(out["present_fields"]) == len(fields)
            and data.get("Code", "Success") == "Success"
        )
        # Do not return arbitrary metadata strings, even from successful bodies.
        expiration = data.get("Expiration", "")
        if isinstance(expiration, str) and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", expiration
        ):
            out["expiration"] = expiration
    except (ValueError, TypeError, UnicodeError):
        out["invalid_json"] = True
    return out


def _imds(opts, budget):
    if opts["skip_imds"]:
        return {"skipped": "skip_imds"}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    out = {"endpoints": [], "credentials_redacted": True, "truncated": False}
    for base in IMDS_BASES:
        if not budget.remaining():
            out["truncated"] = True
            break
        entry = {"endpoint": base, "instance_profile_credentials": []}
        token_meta, token_body = _http(
            opener, base + "/latest/api/token", opts, budget, "PUT",
            {"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        entry["imdsv2_token"] = token_meta
        token = None
        if token_meta.get("status") == 200 and not token_meta.get("truncated"):
            candidate = token_body.decode("ascii", "ignore").strip()
            if candidate and re.fullmatch(r"[!-~]{1,4096}", candidate):
                token = candidate
        entry["imdsv2_token_obtained"] = token is not None
        role_url = base + "/latest/meta-data/iam/security-credentials/"
        # Probe the metadata root: a missing instance profile returns 404 at the
        # IAM path even when IMDSv1 is enabled.
        v1_meta, _ = _http(opener, base + "/latest/meta-data/", opts, budget)
        entry["imdsv1"] = v1_meta
        entry["imdsv1_enabled"] = (
            True if v1_meta.get("status") == 200
            else False if v1_meta.get("status") == 401 else None
        )
        headers = {"X-aws-ec2-metadata-token": token} if token else {}
        role_meta, role_body = _http(opener, role_url, opts, budget, headers=headers)
        entry["role_listing"] = role_meta
        roles = []
        if role_meta.get("status") == 200 and not role_meta.get("truncated"):
            roles = [
                line.strip() for line in role_body.decode("utf-8", "replace").splitlines()
                if ROLE_NAME.fullmatch(line.strip())
            ]
        entry["roles_truncated"] = len(roles) > 4
        for role in roles[:4]:
            if not budget.remaining():
                out["truncated"] = True
                break
            meta, body = _http(opener, role_url + urllib.parse.quote(role), opts, budget,
                               headers=headers)
            entry["instance_profile_credentials"].append(
                {"role": role, **_credential_summary(meta, body)}
            )
        if budget.remaining():
            meta, body = _http(
                opener,
                base + "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
                opts, budget, headers=headers,
            )
            entry["instance_identity_credentials"] = _credential_summary(meta, body)
        else:
            out["truncated"] = True
        entry["http_response_received"] = any(
            "status" in check for check in (token_meta, v1_meta, role_meta)
        )
        out["endpoints"].append(entry)
    return out


def _cap_names(mask):
    return [
        "CAP_" + name for bit, name in enumerate(CAP_NAMES)
        if mask & (1 << bit)
    ]


def _file_caps(raw):
    if len(raw) < 12:
        raise ValueError()
    magic, low_permitted, low_inheritable = struct.unpack_from("<III", raw)
    revision = magic >> 24
    sizes = {1: 12, 2: 20, 3: 24}
    if revision not in sizes or len(raw) != sizes[revision]:
        raise ValueError()
    permitted, inheritable = low_permitted, low_inheritable
    if revision >= 2:
        high_permitted, high_inheritable = struct.unpack_from("<II", raw, 12)
        permitted |= high_permitted << 32
        inheritable |= high_inheritable << 32
    out = {
        "permitted": _cap_names(permitted), "inheritable": _cap_names(inheritable),
        "effective_flag": bool(magic & 1),
    }
    if revision == 3:
        out["root_uid"] = struct.unpack_from("<I", raw, 20)[0]
    return out


def _access(path, mode):
    if os.access in os.supports_effective_ids:
        return os.access(path, mode, effective_ids=True)
    return os.access(path, mode)


def _privileges(opts, budget):
    out = {
        "process": {}, "setuid_setgid_files": [], "file_capabilities": [],
        "scan_roots": {}, "capability_xattrs_supported": hasattr(os, "getxattr"),
        "capability_xattr_errors": 0,
    }
    try:
        text, truncated = _text("/proc/self/status")
        out["status_truncated"] = truncated
        for line in text.splitlines():
            name, sep, value = line.partition(":")
            if sep and name in ("NoNewPrivs", "Seccomp", "Seccomp_filters"):
                out["process"][name] = int(value.strip())
            elif sep and name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                out["process"][name] = _cap_names(int(value.strip(), 16))
    except (OSError, ValueError) as exc:
        out["process"].update(_error(exc))
    seen_roots = set()
    for root in BINARY_ROOTS:
        real_root = os.path.realpath(root)
        if real_root in seen_roots:
            continue
        seen_roots.add(real_root)
        coverage = {}
        for path, info in _walk(root, opts["max_files"], budget, coverage):
            if not info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                out["setuid_setgid_files"].append({
                    **_file_info(path, info),
                    "setuid": bool(info.st_mode & stat.S_ISUID),
                    "setgid": bool(info.st_mode & stat.S_ISGID),
                    "executable_by_current_user": _access(path, os.X_OK),
                })
            if hasattr(os, "getxattr"):
                try:
                    raw = os.getxattr(path, "security.capability")
                    out["file_capabilities"].append({
                        **_file_info(path, info), **_file_caps(raw),
                        "executable_by_current_user": _access(path, os.X_OK),
                    })
                except OSError as exc:
                    if exc.errno not in (
                        errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)
                    ):
                        out["capability_xattr_errors"] += 1
                except ValueError:
                    out["capability_xattr_errors"] += 1
        out["scan_roots"][root] = coverage
    return out


def _sudo_rules(text):
    """Keep run-as identities, tags, and executable names; discard arguments."""
    rules = []
    current = None
    current_tags = []
    for line in text.splitlines():
        match = re.match(r"^\s*\(([^)]+)\)\s*(.*)$", line)
        if match:
            run_as = match.group(1)
            current = {
                "run_as": run_as if re.fullmatch(r"[\w#%:,* .@+-]+", run_as) else "[redacted]",
                "commands": [],
            }
            rules.append(current)
            current_tags = []
            tail = match.group(2)
        elif current is not None and line.startswith((" ", "\t")):
            tail = line.strip()
        else:
            current = None
            continue
        for piece in tail.split(","):
            piece = piece.strip()
            tag_prefix = re.match(r"^(?:[A-Z_]+:\s*)+", piece)
            if tag_prefix:
                # Tags carry across comma-separated commands in a sudo rule.
                for tag in re.findall(r"([A-Z_]+):", tag_prefix.group()):
                    opposites = {
                        "PASSWD": "NOPASSWD", "NOPASSWD": "PASSWD",
                        "EXEC": "NOEXEC", "NOEXEC": "EXEC",
                        "SETENV": "NOSETENV", "NOSETENV": "SETENV",
                    }
                    current_tags = [old for old in current_tags if old != opposites.get(tag)]
                    if tag not in current_tags:
                        current_tags.append(tag)
                command = piece[tag_prefix.end():].strip()
            else:
                command = piece
            first = command.split(None, 1)[0] if command else ""
            if first in ("ALL", "!ALL") or re.fullmatch(r"!?/[\w./*?+@%:=~-]+", first):
                current["commands"].append({
                    "executable": first, "tags": list(current_tags),
                    "negated": first.startswith("!"),
                    "arguments_redacted": len(command.split(None, 1)) > 1,
                })
    return rules


def _sudo(opts, budget):
    if opts["skip_sudo"]:
        return {"skipped": "skip_sudo"}
    path = shutil.which("sudo")
    if not path:
        return {"available": False}
    try:
        result = subprocess.run(
            [path, "-n", "-l"], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, errors="replace", timeout=budget.timeout(3),
            env=dict(os.environ, LC_ALL="C"),
        )
        return {
            "available": True, "returncode": result.returncode,
            "listing_succeeded": result.returncode == 0,
            "rules": _sudo_rules(result.stdout[:READ_LIMIT]),
            "output_truncated": len(result.stdout) > READ_LIMIT,
            "authentication_required": "password is required" in result.stderr.lower(),
            "not_allowed": "not allowed" in (result.stdout + result.stderr).lower(),
            "arguments_and_diagnostics_redacted": True,
        }
    except Exception as exc:
        return {"available": True, **_error(exc)}


def _proc_address(value):
    raw = bytes.fromhex(value)
    if len(raw) not in (4, 16):
        raise ValueError()
    if sys.byteorder == "little":
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    return str(ipaddress.ip_address(raw))


def _listeners():
    out = {"tcp": [], "udp": [], "unix": [], "errors": [], "truncated": False}
    for name, kind in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            text, truncated = _text("/proc/net/" + name)
            out["truncated"] |= truncated
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10 or fields[3] != ("0A" if kind == "tcp" else "07"):
                    continue
                address, port = fields[1].split(":")
                if int(port, 16) == 0:
                    continue
                if len(out[kind]) >= 256:
                    out["truncated"] = True
                    break
                out[kind].append({
                    "address": _proc_address(address), "port": int(port, 16),
                    "uid": int(fields[7]), "inode": fields[9],
                    "ipv6": name.endswith("6"),
                })
        except (OSError, ValueError) as exc:
            out["errors"].append({"table": name, **_error(exc)})
    try:
        text, truncated = _text("/proc/net/unix")
        out["truncated"] |= truncated
        for line in text.splitlines()[1:]:
            fields = line.split(None, 7)
            if len(fields) < 8:
                continue
            accepting = bool(int(fields[3], 16) & 0x10000)
            datagram = fields[4] == "0002"
            if not accepting and not datagram:
                continue
            if len(out["unix"]) >= 256:
                out["truncated"] = True
                break
            out["unix"].append({
                "path": fields[7], "type": "datagram" if datagram else "stream",
                "inode": fields[6],
            })
    except (OSError, ValueError) as exc:
        out["errors"].append({"table": "unix", **_error(exc)})
    return out


def _container_sockets(opts, budget):
    out = {
        "container_markers": [
            path for path in ("/.dockerenv", "/run/.containerenv") if os.path.exists(path)
        ],
        "cgroup_markers": [], "sockets": [], "errors": [],
        "api_authorization_tested": False,
    }
    try:
        text, _ = _text("/proc/1/cgroup")
        out["cgroup_markers"] = [
            name for name in ("docker", "kubepods", "containerd", "lxc", "libpod")
            if name in text
        ]
    except OSError as exc:
        out["errors"].append({"check": "cgroup", **_error(exc)})
    paths = (
        "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
        "/run/crio/crio.sock", "/run/podman/podman.sock",
        "/run/user/{}/docker.sock".format(os.geteuid()),
        "/run/user/{}/podman/podman.sock".format(os.geteuid()),
    )
    seen = set()
    for path in paths:
        if not budget.remaining():
            out["truncated"] = True
            break
        try:
            info = os.stat(path)
            if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) in seen:
                continue
            seen.add((info.st_dev, info.st_ino))
            row = {**_file_info(path, info), "connect_ok": False,
                   "readable": _access(path, os.R_OK), "writable": _access(path, os.W_OK)}
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(budget.timeout(opts["timeout_s"]))
                    connection.connect(path)
                row["connect_ok"] = True
            except OSError as exc:
                row.update(_error(exc))
            out["sockets"].append(row)
        except FileNotFoundError:
            continue
        except OSError as exc:
            out["errors"].append({"path": path, **_error(exc)})
    return out


def _target(address, port, source):
    parsed = ipaddress.ip_address(address)
    port = int(port)
    if parsed.is_unspecified or parsed.is_multicast or not 1 <= port <= 65535:
        raise ValueError()
    return {"address": str(parsed), "port": port, "source": source,
            "internal": parsed.is_private or parsed.is_link_local or parsed.is_loopback}


def _default_targets():
    targets, errors = [], []
    try:
        text, _ = _text("/etc/resolv.conf")
        for line in text.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                try:
                    target = _target(fields[1], 53, "dns_resolver")
                    if target["internal"] and len(targets) < 4:
                        targets.append(target)
                except ValueError:
                    continue
    except OSError as exc:
        errors.append({"check": "dns_configuration", **_error(exc)})
    try:
        text, _ = _text("/proc/net/route")
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 3 == 3:
                try:
                    target = _target(_proc_address(fields[2]), 443, "default_gateway")
                    if target["internal"]:
                        targets.append(target)
                except ValueError:
                    continue
    except (OSError, ValueError) as exc:
        errors.append({"check": "routing_table", **_error(exc)})
    return targets, errors


def _network(opts, budget):
    if opts["skip_network"]:
        return {"skipped": "skip_network"}
    out = {"targets": [], "invalid_targets": [], "truncated": False,
           "failed_connections_are_inconclusive": True}
    raw = opts["targets"]
    pieces = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
    selected = []
    for index, piece in enumerate(pieces[:MAX_TARGETS]):
        if not isinstance(piece, str) or not piece.strip():
            continue
        try:
            address, port = piece.strip().rsplit(":", 1)
            if address.startswith("[") and address.endswith("]"):
                address = address[1:-1]
            selected.append(_target(address, port, "provided"))
        except (ValueError, TypeError):
            out["invalid_targets"].append({"index": index, "error": "expected_literal_ip_and_port"})
    defaults, out["discovery_errors"] = _default_targets()
    seen = set()
    for target in selected + defaults:
        key = target["address"], target["port"]
        if key in seen:
            continue
        seen.add(key)
        if len(out["targets"]) >= MAX_TARGETS or not budget.remaining():
            out["truncated"] = True
            break
        row = {**target, "connect_ok": False}
        started = time.monotonic()
        family = socket.AF_INET6 if ":" in target["address"] else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(budget.timeout(opts["timeout_s"]))
                connection.connect(key)
            row["connect_ok"] = True
            row["result"] = "connected"
        except OSError as exc:
            row.update(_error(exc))
            row["result"] = "refused" if exc.errno == errno.ECONNREFUSED else "inconclusive"
        row["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        out["targets"].append(row)
    out["truncated"] |= len(pieces) > MAX_TARGETS
    return out


def _summarize(report):
    findings = []

    def add(code, severity, title, must_fix=False):
        findings.append({"code": code, "severity": severity, "title": title, "must_fix": must_fix})

    endpoints = report.get("imds", {}).get("endpoints", [])
    profile = any(
        row.get("credentials_present")
        for endpoint in endpoints
        for row in endpoint.get("instance_profile_credentials", [])
    )
    identity = any(
        endpoint.get("instance_identity_credentials", {}).get("credentials_present")
        for endpoint in endpoints
    )
    if profile:
        add("imds_instance_profile_credentials", "critical",
            "IMDS returned instance-profile credentials to the plugin user.", True)
    if identity:
        add("imds_instance_identity_credentials", "high",
            "IMDS returned instance-identity credentials; these have service-limited authority.", True)
    if any(endpoint.get("imdsv1_enabled") for endpoint in endpoints):
        add("imdsv1_enabled", "medium", "IMDS accepts a metadata request without a token.")
    if report.get("identity", {}).get("is_root"):
        add("plugin_runs_as_root", "high", "The plugin executes with effective UID 0.")
    if any(row.get("connect_ok") for row in report.get("container", {}).get("sockets", [])):
        add("container_runtime_socket", "high",
            "The plugin user can connect to a container runtime socket; review its API permissions.")
    env = report.get("environment", {})
    processes = report.get("process_environments", {}).get("processes", [])
    if env.get("nonempty_credential_like_names") or any(
        row.get("nonempty_credential_like_names") for row in processes
    ):
        add("credential_like_environment", "high",
            "Nonempty environment variables with credential-like names are readable.")
    files = [
        row for root in report.get("files", {}).get("roots", {}).values()
        for row in root.get("readable_files", [])
    ]
    if any(row["path"] in ("/etc/shadow", "/etc/gshadow") for row in files):
        add("shadow_readable", "high", "A password-hash file in /etc is readable.")
    if any(row.get("sensitive_name") for row in files):
        add("sensitive_file_candidates", "medium",
            "Readable files have names associated with credentials; review their contents separately.")
    if any(
        not command.get("negated")
        for rule in report.get("sudo", {}).get("rules", [])
        for command in rule.get("commands", [])
    ):
        add("sudo_rules", "high", "Sudo policy lists allowed commands; review run-as identities and tags.")
    effective = set(report.get("privileges", {}).get("process", {}).get("CapEff", []))
    if effective & DANGEROUS_CAPS:
        add("dangerous_process_capabilities", "high", "The plugin process has powerful effective capabilities.")
    if any(
        set(row.get("permitted", [])) & DANGEROUS_CAPS
        and row.get("executable_by_current_user")
        for row in report.get("privileges", {}).get("file_capabilities", [])
    ):
        add("powerful_file_capabilities", "medium",
            "An executable file has powerful capabilities; review mount and execution restrictions.")
    if any(
        row.get("connect_ok") and row.get("internal")
        for row in report.get("network", {}).get("targets", [])
    ):
        add("internal_tcp_access", "info", "The plugin can establish TCP connections to internal endpoints.")
    return {
        "headline": findings[0]["title"] if findings else "No priority finding confirmed within the probe limits.",
        "imds_credentials_observed": bool(profile or identity),
        "must_fix": [row["code"] for row in findings if row["must_fix"]],
        "findings": findings,
        "skipped_sections": [
            name for name, section in report.items()
            if isinstance(section, dict) and "skipped" in section
        ],
    }


def process_request(influxdb3_local, query_parameters, request_headers, request_body, args=None):
    opts = _options(query_parameters, args)
    budget = _Budget(opts["budget_s"])
    started = time.monotonic()
    report = {
        "probe": "access_probe", "version": 1,
        "limits": {name: opts[name] for name in ("timeout_s", "budget_s", "max_files", "max_pids")},
    }
    sections = (
        ("identity", _identity),
        ("imds", lambda: _imds(opts, budget)),
        ("environment", lambda: _env_summary(os.environ)),
        ("process_environments", lambda: _process_environments(opts, budget)),
        ("listeners", _listeners),
        ("container", lambda: _container_sockets(opts, budget)),
        ("sudo", lambda: _sudo(opts, budget)),
        ("network", lambda: _network(opts, budget)),
        ("files", lambda: _readable_files(opts, budget)),
        ("privileges", lambda: _privileges(opts, budget)),
    )
    for name, check in sections:
        if not budget.remaining():
            report[name] = {"skipped": "time_budget_exhausted"}
            continue
        try:
            report[name] = check()
        except Exception as exc:
            report[name] = _error(exc)
    report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    report["budget_exhausted"] = not bool(budget.remaining())
    report["summary"] = _summarize(report)
    # Avoid copying the report (including paths and variable names) into service logs.
    if influxdb3_local is not None:
        influxdb3_local.info("access_probe completed")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--targets", default="", help="comma-separated literal IP:port pairs")
    parser.add_argument("--timeout-s", type=float, default=1)
    parser.add_argument("--budget-s", type=float, default=30)
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--max-pids", type=int, default=128)
    for option in ("imds", "network", "sudo"):
        parser.add_argument("--skip-" + option, action="store_true")
    parsed = vars(parser.parse_args())
    print(json.dumps(process_request(None, parsed, {}, b""), indent=2))
