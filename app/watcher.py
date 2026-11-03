#!/usr/bin/env python3
"""notifyarr: watch Docker containers (and the Unraid host) and alert via Telegram / email.

Sources
  * Docker events: crashes, OOM kills, unhealthy healthchecks, restart loops
  * Container logs: lines matched against [[rules]] in config.toml
  * Host syslog (optional): disk / filesystem / kernel errors, login attempts
  * Unraid notifications (optional): array, SMART, parity, temperature, etc.
  * CrowdSec LAPI (optional): new bans, faulty bans of trusted IPs, geoblocks

Severity is info / warning / critical. Quiet hours hold back anything below
quiet_hours.allow and can send a digest when they end.

Pure Python standard library (3.11+). Secrets come from env vars, everything else
from config.toml.
"""
import http.client
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime
from email.message import EmailMessage

log = logging.getLogger("notifyarr")

SEV = {"off": 0, "info": 1, "warning": 2, "critical": 3}
SEV_ICON = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
CAT_ICON = {
    "crash": "🛑", "oom": "💥", "restart_loop": "🔁", "unhealthy": "🩺", "recovered": "✅",
    "error": "⚠️", "security": "🛡️", "malware": "🦠", "breach": "🚨", "ban": "⛔",
    "faulty_ban": "❗", "geoblock": "🌍", "backup": "💾", "disk": "💽", "host": "🖥️", "unraid": "🟠",
}


# =========================================================================== config
def env(name, default=""):
    return os.environ.get(name, default).strip()


# Settings made in the GUI (channels, passwords, keys) live in /config/settings.json, readable only by
# the container's root user (mode 600). Environment variables still work and are used as a fallback.
SETTINGS = {}
SETTINGS_KEYS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_THREAD_ID", "TELEGRAM_MIN_SEVERITY",
                 "SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_FROM",
                 "EMAIL_TO", "EMAIL_MIN_SEVERITY", "CROWDSEC_BOUNCER_KEY", "GUI_PASSWORD_HASH")
SECRET_KEYS = ("TELEGRAM_BOT_TOKEN", "SMTP_PASSWORD", "CROWDSEC_BOUNCER_KEY", "GUI_PASSWORD_HASH")


def settings_path():
    return os.path.join(os.path.dirname(env("CONFIG_FILE", "/config/config.toml")), "settings.json")


def load_settings():
    SETTINGS.clear()
    try:
        with open(settings_path()) as f:
            SETTINGS.update({k: v for k, v in json.load(f).items() if k in SETTINGS_KEYS})
    except (OSError, ValueError):
        pass


def save_settings(updates):
    load_settings()
    for k, v in updates.items():
        if k not in SETTINGS_KEYS:
            continue
        if v is None or v == "":
            SETTINGS.pop(k, None)
        else:
            SETTINGS[k] = str(v)
    p = settings_path()
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(SETTINGS, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def setting(name, default=""):
    v = SETTINGS.get(name)
    return str(v).strip() if v not in (None, "") else env(name, default)


def load_config():
    path = env("CONFIG_FILE", "/config/config.toml")
    cfg = {}
    defaults = os.path.join(os.path.dirname(os.path.abspath(__file__)), "defaults")
    if not os.path.exists(path) and os.path.isdir(defaults):  # first start: seed /config
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            for f in os.listdir(defaults):
                dst = os.path.join(os.path.dirname(path), f)
                if not os.path.exists(dst):
                    shutil.copy2(os.path.join(defaults, f), dst)
            log.info("created default config in %s", os.path.dirname(path))
        except OSError as e:
            log.warning("could not create default config: %s", e)
    if os.path.exists(path):
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        log.info("loaded config from %s", path)
    else:
        log.warning("no config file at %s, using built-in defaults", path)
    return cfg


RAW = {}
CFG = {}


def setup_config():
    global RAW
    RAW = load_config()
    load_settings()
    g = RAW
    c = CFG
    c["host_label"] = g.get("host_label") or env("HOST_LABEL") or "docker"
    c["cooldown"] = int(g.get("cooldown_seconds", 300))
    c["remind_hours"] = float(g.get("remind_hours", 24))
    c["startup_message"] = bool(g.get("startup_message", True))

    cont = g.get("containers", {})
    c["include"] = set(cont.get("include", []))
    c["exclude"] = set(cont.get("exclude", []))

    ev = g.get("events", {})
    c["events_enabled"] = bool(ev.get("enabled", True))
    c["ev"] = {
        "crash": ev.get("crash", "critical"),
        "oom": ev.get("oom", "critical"),
        "restart_loop": ev.get("restart_loop", "critical"),
        "unhealthy": ev.get("unhealthy", "warning"),
        "recovered": ev.get("recovered", "info"),
        "clean_exit": ev.get("clean_exit", "off"),
    }
    c["restart_loop_count"] = int(ev.get("restart_loop_count", 3))
    c["restart_loop_window"] = int(ev.get("restart_loop_window_minutes", 10)) * 60

    lg = g.get("logs", {})
    c["watch_logs"] = bool(lg.get("enabled", True))
    c["batch_seconds"] = float(lg.get("batch_seconds", 10))
    c["max_lines"] = int(lg.get("max_lines", 10))

    c["rules"] = []
    for r in g.get("rules", DEFAULT_RULES):
        if not r.get("enabled", True):
            continue
        c["rules"].append({
            "ip": r.get("ip", "any"),  # any | untrusted | new
            "name": r["name"],
            "re": re.compile(r["pattern"]),
            "severity": r.get("severity", "warning"),
            "category": r.get("category", "error"),
            "sources": set(r.get("sources", [])),
            "exclude_sources": set(r.get("exclude_sources", [])),
        })
    c["ignore"] = []
    for r in g.get("ignore", []):
        c["ignore"].append({"re": re.compile(r["pattern"]), "sources": set(r.get("sources", []))})

    q = g.get("quiet_hours", {})
    c["quiet"] = {
        "enabled": bool(q.get("enabled", False)),
        "start": parse_hm(q.get("start", "23:00")),
        "end": parse_hm(q.get("end", "07:00")),
        "days": [d.lower()[:3] for d in q.get("days", [])],
        "allow": q.get("allow", "critical"),
        "digest": bool(q.get("digest", True)),
    }

    h = g.get("host", {})
    c["syslog"] = h.get("syslog_path", "") if h.get("syslog", False) else ""
    c["syslog_name"] = h.get("name", "unraid")
    c["unraid_notify"] = h.get("notifications_path", "") if h.get("unraid_notifications", False) else ""
    c["unraid_map"] = {
        "alert": h.get("unraid_alert", "critical"),
        "warning": h.get("unraid_warning", "warning"),
        "normal": h.get("unraid_normal", "info"),
    }

    cs = g.get("crowdsec", {})
    c["cs"] = {
        "enabled": bool(cs.get("enabled", False)),
        "url": cs.get("url", "http://crowdsec:8080").rstrip("/"),
        "key": setting("CROWDSEC_BOUNCER_KEY"),
        "poll": int(cs.get("poll_seconds", 30)),
        "origins": set(cs.get("origins", ["crowdsec", "cscli"])),
        "ban": cs.get("ban_severity", "info"),
        "geoblock": cs.get("geoblock_severity", "info"),
        "faulty": cs.get("faulty_ban_severity", "critical"),
        "ignore_scenarios": [re.compile(p) for p in cs.get("ignore_scenarios", [])],
        "geoblock_scenarios": re.compile(cs.get("geoblock_scenarios", r"(?i)geo|country")),
    }

    ips = g.get("ips", {})
    c["trusted_static"] = ips.get("trusted", DEFAULT_TRUSTED)
    c["trusted_file"] = ips.get("trusted_file", "/config/trusted_ips.txt")
    c["seen_file"] = ips.get("seen_file", "/config/seen_ips.json")
    TRUST.load()

    c["tg_commands"] = bool(g.get("telegram", {}).get("commands", True))
    pv = g.get("privacy", {})
    c["redact"] = bool(pv.get("redact_secrets", True))
    c["include_log_lines"] = bool(pv.get("include_log_lines", True))
    c["redact_extra"] = [(re.compile(x), "***") for x in pv.get("extra_patterns", [])]
    sm = g.get("disk_health", {})
    c["smart"] = {
        "enabled": bool(sm.get("enabled", False)),
        "path": sm.get("smart_path", "/host/emhttp/smart"),
        "every": int(sm.get("check_hours", 6)) * 3600,
        "life_warn": float(sm.get("ssd_life_warn_percent", 20)),
        "life_crit": float(sm.get("ssd_life_critical_percent", 10)),
        "hours_warn": float(sm.get("hdd_age_warn_years", 6)) * 8766,
    }

    dk = g.get("storage", g.get("disks", {}))
    c["disks"] = {
        "enabled": bool(dk.get("enabled", False)),
        "paths": dict(dk.get("paths", {})),
        "array": dk.get("array", ""),
        "auto_pools": bool(dk.get("auto_pools", False)),
        "mnt": dk.get("mnt_path", "/host/mnt"),
        "docker_dir": dk.get("docker_dir", ""),
        "log_dir": dk.get("log_dir", ""),
        "log_warn": float(dk.get("log_warn_percent", 75)),
        "container_log_mb": float(dk.get("container_log_mb", 0)),
        "warn": float(dk.get("warn_percent", 85)),
        "crit": float(dk.get("critical_percent", 95)),
        "every": int(dk.get("check_minutes", 15)) * 60,
    }
    ups = g.get("ups", {})
    c["ups"] = {
        "enabled": bool(ups.get("enabled", False)),
        "kind": ups.get("type", "apcupsd").lower(),
        "host": ups.get("host", "172.17.0.1"),
        "port": int(ups.get("port", 3551 if ups.get("type", "apcupsd").lower() == "apcupsd" else 3493)),
        "name": ups.get("ups_name", "ups"),
        "every": int(ups.get("check_seconds", 30)),
        "on_battery": ups.get("on_battery_severity", "critical"),
        "low_battery": ups.get("low_battery_severity", "critical"),
        "health": ups.get("battery_health_severity", "warning"),
        "max_age_years": float(ups.get("battery_max_age_years", 3)),
        "min_charge": float(ups.get("min_charge_percent", 90)),
        "min_runtime": float(ups.get("min_runtime_minutes", 5)),
    }
    bk = g.get("backups", {})
    c["backups"] = {"enabled": bool(bk.get("enabled", False)), "checks": list(bk.get("checks", [])),
                    "every": int(bk.get("check_hours", 1)) * 3600, "severity": bk.get("severity", "warning")}
    hw = g.get("hardware", {})
    c["hw"] = {
        "enabled": bool(hw.get("enabled", False)),
        "every": int(hw.get("check_hours", 24)) * 3600,
        "bios_age_years": float(hw.get("bios_age_years", 2)),
        "cmos_check": bool(hw.get("cmos_check", True)),
        "ipmi": bool(hw.get("ipmi", False)),
        "vbat_min": float(hw.get("vbat_min_volts", 2.8)),
        "dmi": hw.get("dmi_path", "/sys/class/dmi/id"),
        "smart_dir": hw.get("smart_path", "/host/emhttp/smart"),
        "severity": hw.get("severity", "info"),
    }
    up = g.get("updates", {})
    c["updates"] = {
        "enabled": bool(up.get("enabled", False)),
        "every": int(up.get("check_hours", 24)) * 3600,
        "severity": up.get("severity", "info"),
        "skip": set(up.get("exclude", [])),
    }
    ce = g.get("certs", {})
    c["certs"] = {
        "enabled": bool(ce.get("enabled", False)),
        "hosts": list(ce.get("hosts", [])),
        "warn": int(ce.get("warn_days", 14)),
        "crit": int(ce.get("critical_days", 3)),
        "every": int(ce.get("check_hours", 12)) * 3600,
    }
    tk = g.get("unraid_tasks", {})
    c["tasks"] = {
        "enabled": bool(tk.get("enabled", False)),
        "emhttp": tk.get("emhttp_path", "/host/emhttp"),
        "mover_pid": tk.get("mover_pid", "/host/run/mover.pid"),
        "max_hours": {"parity_check": float(tk.get("parity_check_max_hours", 24)),
                      "read_check": float(tk.get("read_check_max_hours", 24)),
                      "rebuild": float(tk.get("rebuild_max_hours", 36)),
                      "clear": float(tk.get("clear_max_hours", 36)),
                      "mover": float(tk.get("mover_max_hours", 6))},
        "stall_minutes": int(tk.get("stall_minutes", 30)),
        "start_severity": tk.get("start_severity", "info"),
        "finish_severity": tk.get("finish_severity", "info"),
        "mover_finish_severity": tk.get("mover_finish_severity", "off"),
        "disk_temp_critical": int(tk.get("disk_temp_critical", 55)),
        "every": int(tk.get("check_seconds", 60)),
    }
    wg = g.get("wireguard", {})
    c["wg"] = {
        "enabled": bool(wg.get("enabled", False)),
        "ping": list(wg.get("ping", [])),
        "handshake": bool(wg.get("check_handshakes", False)),
        "peers": dict(wg.get("peers", {})),
        "max_handshake_minutes": int(wg.get("max_handshake_minutes", 5)),
        "every": int(wg.get("check_minutes", 2)) * 60,
        "severity": wg.get("severity", "warning"),
    }
    rs = g.get("resources", {})
    c["res"] = {
        "enabled": bool(rs.get("enabled", False)),
        "every": int(rs.get("check_seconds", 60)),
        "size_every": int(rs.get("disk_size_check_minutes", 30)) * 60,
        "for_minutes": float(rs.get("for_minutes", 5)),
        "severity": rs.get("severity", "warning"),
        "defaults": {k: rs.get(k, 0) for k in RES_KEYS},
        "per": {n: dict(v) for n, v in rs.get("containers", {}).items()},
    }
    c["state_file"] = g.get("state_file", "/config/state.json")
    rb = g.get("reboot", {})
    c["reboot"] = {"enabled": bool(rb.get("enabled", True)), "clean": rb.get("clean_severity", "info"),
                   "unclean": rb.get("unclean_severity", "critical")}
    c["state_file"] = rb.get("state_file", c["state_file"])
    nt = g.get("internet", {})
    tg = []
    for t in nt.get("targets", ["1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:443"]):
        h, _, prt = t.rpartition(":")
        tg.append((h, int(prt)))
    c["net"] = {"enabled": bool(nt.get("enabled", True)), "targets": tg,
                "every": int(nt.get("check_seconds", 60)), "fail_count": int(nt.get("fail_count", 3)),
                "severity": nt.get("severity", "warning")}
    c["http_checks"] = list(g.get("http_checks", []))
    c["http_every"] = int(g.get("http_check_minutes", 5)) * 60
    cu = g.get("cleanup", {})
    c["cleanup"] = {
        "enabled": bool(cu.get("enabled", False)),
        "every": int(cu.get("check_hours", 24)) * 3600,
        "severity": cu.get("severity", "info"),
        "min_mb": float(cu.get("unused_images_min_mb", 500)),
        "stopped_days": int(cu.get("stopped_days", 30)),
        "writable_gb": float(cu.get("writable_layer_gb", 10)),
        "appdata": cu.get("appdata_path", "/host/mnt/user/appdata"),
        "appdata_host_prefixes": list(cu.get("appdata_host_prefixes",
                                             ["/mnt/user/appdata", "/mnt/cache/appdata", "/mnt/disk1/appdata"])),
        "appdata_ignore": list(cu.get("appdata_ignore", [])),
        "growth_gb_per_day": float(cu.get("growth_gb_per_day", 20)),
        "size_budget": float(cu.get("size_seconds_per_folder", 20)),
    }
    hb = g.get("heartbeat", {})
    c["heartbeat"] = {"enabled": bool(hb.get("enabled", True)), "time": parse_hm(hb.get("time", "09:00"))}

    c["docker_socket"] = env("DOCKER_SOCKET", "/var/run/docker.sock")
    c["docker_host"] = env("DOCKER_HOST", "")
    c["tg_token"] = setting("TELEGRAM_BOT_TOKEN")
    c["tg_api"] = env("TELEGRAM_API_URL", "https://api.telegram.org").rstrip("/")
    c["tg_chat"] = setting("TELEGRAM_CHAT_ID")
    c["tg_thread"] = setting("TELEGRAM_THREAD_ID")
    c["smtp_host"] = setting("SMTP_HOST")
    c["smtp_port"] = int(setting("SMTP_PORT", "587"))
    c["smtp_user"] = setting("SMTP_USER")
    c["smtp_pass"] = setting("SMTP_PASSWORD")
    c["smtp_security"] = setting("SMTP_SECURITY", "starttls").lower()
    c["email_from"] = setting("EMAIL_FROM") or setting("SMTP_USER")
    c["email_to"] = [x.strip() for x in setting("EMAIL_TO").split(",") if x.strip()]
    c["email_min"] = setting("EMAIL_MIN_SEVERITY", "info")
    c["tg_min"] = setting("TELEGRAM_MIN_SEVERITY", "info")
    c["own_secrets"] = [c["tg_token"], c["smtp_pass"], setting("CROWDSEC_BOUNCER_KEY"), env("GUI_PASSWORD")]
    REMIND.update(load_state().get("remind", {}))


def parse_hm(s):
    h, m = str(s).split(":")
    return int(h) * 60 + int(m)


DEFAULT_RULES = [
    {"name": "Fatal error", "pattern": r"(?i)\b(fatal|panic|critical|emerg(ency)?)\b",
     "severity": "critical", "category": "error"},
    {"name": "Error", "pattern": r"(?i)\b(error|exception|traceback)\b",
     "severity": "warning", "category": "error"},
]


DEFAULT_TRUSTED = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                   "::1/128", "fc00::/7", "fe80::/10"]

IP_RE = re.compile(
    r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])"
)


class TrustStore:
    """Trusted IPs/ranges = config list + trusted_ips.txt (editable, reloaded on change, and
    written by the Telegram /trust command). Also remembers which untrusted IPs were seen."""

    def __init__(self):
        self.lock = threading.Lock()
        self.static, self.dynamic, self.mtime = [], [], None
        self.seen = {}

    def load(self):
        with self.lock:
            self.static = [self._net(n) for n in CFG["trusted_static"]]
            self.static = [n for n in self.static if n]
            self._load_file()
            try:
                with open(CFG["seen_file"]) as f:
                    self.seen = json.load(f)
            except (OSError, ValueError):
                self.seen = {}

    @staticmethod
    def _net(s):
        try:
            return ipaddress.ip_network(str(s).strip(), strict=False)
        except ValueError:
            log.warning("ignoring invalid IP/range %r", s)
            return None

    def _load_file(self):
        path = CFG["trusted_file"]
        try:
            m = os.path.getmtime(path)
        except OSError:
            self.dynamic, self.mtime = [], None
            return
        if m == self.mtime:
            return
        nets = []
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    n = self._net(line.split()[0])
                    if n:
                        nets.append(n)
        self.dynamic, self.mtime = nets, m
        log.info("loaded %d trusted entries from %s", len(nets), path)

    def match(self, ip):
        """Return the trusted network containing ip (or overlapping a range), else None."""
        net = self._net(ip) if not isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ip
        if net is None:
            return None
        with self.lock:
            self._load_file()
            for t in self.static + self.dynamic:
                if t.version == net.version and net.overlaps(t):
                    return t
        return None

    def add(self, entry, note=""):
        n = self._net(entry)
        if not n:
            return None
        with self.lock:
            with open(CFG["trusted_file"], "a") as f:
                f.write(f"{n}  # {note or 'added'} {datetime.now():%Y-%m-%d %H:%M}\n")
            self.mtime = None
            self._load_file()
            self.seen.pop(str(n.network_address), None)
        return n

    def remove(self, entry):
        n = self._net(entry)
        path = CFG["trusted_file"]
        if not n or not os.path.exists(path):
            return False
        with self.lock:
            with open(path) as f:
                lines = f.readlines()
            keep = [l for l in lines if self._net((l.split("#", 1)[0].split() or [""])[0]) != n]
            with open(path, "w") as f:
                f.writelines(keep)
            self.mtime = None
            self._load_file()
            return len(keep) != len(lines)

    def listing(self):
        with self.lock:
            self._load_file()
            return [str(n) for n in self.static], [str(n) for n in self.dynamic]

    def first_seen(self, ip):
        """True if this untrusted IP has never been seen before (and records it)."""
        with self.lock:
            if ip in self.seen:
                self.seen[ip]["count"] += 1
                new = False
            else:
                self.seen[ip] = {"first": datetime.now().isoformat(timespec="seconds"), "count": 1}
                new = True
            try:
                with open(CFG["seen_file"], "w") as f:
                    json.dump(self.seen, f)
            except OSError:
                pass
            return new


TRUST = TrustStore()


def extract_ips(line):
    out = []
    for m in IP_RE.finditer(line):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if str(ip) not in out:
            out.append(str(ip))
    return out


# =========================================================================== docker api
class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=None):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker_conn(timeout=None):
    if CFG["docker_host"]:
        u = urllib.parse.urlparse(CFG["docker_host"].replace("tcp://", "http://"))
        return http.client.HTTPConnection(u.hostname, u.port or 2375, timeout=timeout)
    return UnixHTTPConnection(CFG["docker_socket"], timeout=timeout)


def docker_get(path, timeout=30):
    c = docker_conn(timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        if r.status >= 400:
            raise RuntimeError(f"Docker API {path} -> {r.status}: {body[:200]!r}")
        return json.loads(body) if body else None
    finally:
        c.close()


def docker_stream(path, timeout=None):
    c = docker_conn(timeout)
    c.request("GET", path)
    r = c.getresponse()
    if r.status >= 400:
        body = r.read()
        c.close()
        raise RuntimeError(f"Docker API {path} -> {r.status}: {body[:200]!r}")
    return c, r


# =========================================================================== privacy / redaction
# Everything that leaves the container (Telegram, email, the GUI's alert history and our own log)
# goes through redact(), so tokens, passwords and API keys that apps print in their logs are masked.
REDACT_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[private key removed]"),
    (re.compile(r"([a-zA-Z][\w+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1***:***@"),          # user:pass@ in URLs
    (re.compile(r"(?i)\b(authorization|proxy-authorization|x-api-key|x-plex-token|x-emby-token|"
                r"x-mediabrowser-token|x-auth-token|cookie|set-cookie)(\s*[:=]\s*)((?:bearer|basic|token)\s+)?[^\s,;]+"),
     r"\1\2\3***"),
    (re.compile(r"(?i)\b([\w-]*(?:api[_-]?key|apikey|token|secret|passw(?:or)?d|passwd|pwd|pass|auth|session|"
                r"sessionid|sid|cookie|signature|sig|credential|private[_-]?key|access[_-]?key)[\w-]*)"
                r"(\\?[\"']?\s*[:=]\s*\\?[\"']?)([^\s\"'&,;)}\]]+)"), r"\1\2***"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "***jwt***"),                # JSON web tokens
    (re.compile(r"\b\d{8,10}:[\w-]{35}\b"), "***bot-token***"),                          # Telegram bot tokens
    (re.compile(r"(?<!sha256:)(?<![\w-])[a-fA-F0-9]{32,}(?![\w-])"), "***key***"),      # *arr-style API keys
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})\b"),
     "***token***"),
]


def redact(text):
    if not text or not CFG.get("redact", True):
        return text
    for secret in CFG.get("own_secrets", []):
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")
    for rx, sub in REDACT_PATTERNS + CFG.get("redact_extra", []):
        text = rx.sub(sub, text)
    return text


# =========================================================================== notifiers
def send_telegram(subject, body, severity, buttons=None):
    if not (CFG["tg_token"] and CFG["tg_chat"]) or SEV[severity] < SEV[CFG["tg_min"]]:
        return
    text = f"{subject}\n\n{body}"
    if len(text) > 4000:
        text = text[:3990] + "\n…"
    data = {"chat_id": CFG["tg_chat"], "text": text, "disable_web_page_preview": "true"}
    if severity == "info":
        data["disable_notification"] = "true"  # silent push for info
    if CFG["tg_thread"]:
        data["message_thread_id"] = CFG["tg_thread"]
    if buttons:
        data["reply_markup"] = json.dumps({"inline_keyboard": [
            [{"text": t, "callback_data": d} for t, d in buttons]]})
    tg_api("sendMessage", data)


def tg_api(method, data, timeout=20):
    req = urllib.request.Request(
        f"{CFG['tg_api']}/bot{CFG['tg_token']}/{method}",
        data=urllib.parse.urlencode(data).encode(),
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def send_email(subject, body, severity, buttons=None):
    if not (CFG["smtp_host"] and CFG["email_to"]) or SEV[severity] < SEV[CFG["email_min"]]:
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = CFG["email_from"]
    msg["To"] = ", ".join(CFG["email_to"])
    if severity == "critical":
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if CFG["smtp_security"] == "ssl":
        s = smtplib.SMTP_SSL(CFG["smtp_host"], CFG["smtp_port"], context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(CFG["smtp_host"], CFG["smtp_port"], timeout=30)
        if CFG["smtp_security"] == "starttls":
            s.starttls(context=ctx)
    try:
        if CFG["smtp_user"]:
            s.login(CFG["smtp_user"], CFG["smtp_pass"])
        s.send_message(msg)
    finally:
        s.quit()


_send_lock = threading.Lock()


STATS = defaultdict(int)
HISTORY = deque(maxlen=500)   # recent alerts (already redacted), shown in the GUI


def deliver(subject, body, severity, buttons=None):
    subject = redact(f"[{CFG['host_label']}] {subject}")
    body = redact(body)
    HISTORY.append({"t": datetime.now().isoformat(timespec="seconds"), "severity": severity,
                    "subject": subject, "body": body})
    STATS[severity] += 1
    log.info("SEND %s %s | %s", severity.upper(), subject, body.replace("\n", " ⏎ ")[:300])
    with _send_lock:
        for name, fn in (("telegram", send_telegram), ("email", send_email)):
            for attempt in range(3):
                try:
                    fn(subject, body, severity, buttons)
                    break
                except Exception as e:  # noqa: BLE001
                    log.warning("%s send failed (attempt %d): %s", name, attempt + 1, e)
                    time.sleep(2 * (attempt + 1))
            else:
                with _outbox_lock:  # keep it and resend when the internet is back
                    if len(_outbox) < 200:
                        _outbox.append((name, fn, subject, body, severity,
                                        datetime.now().strftime("%Y-%m-%d %H:%M")))


_outbox = []
_outbox_lock = threading.Lock()


def flush_outbox():
    with _outbox_lock:
        items, _outbox[:] = _outbox[:], []
    for name, fn, subject, body, severity, when in items:
        try:
            fn(subject, f"(Delayed: originally raised {when})\n\n{body}", severity)
        except Exception as e:  # noqa: BLE001
            log.warning("%s resend failed: %s", name, e)
            with _outbox_lock:
                _outbox.append((name, fn, subject, body, severity, when))


# =========================================================================== quiet hours / rate limiting
def in_quiet_hours(now=None):
    q = CFG["quiet"]
    if not q["enabled"]:
        return False
    now = now or datetime.now()
    minute = now.hour * 60 + now.minute
    s, e = q["start"], q["end"]
    if s <= e:
        inside = s <= minute < e
        day = now
    else:  # window crosses midnight
        inside = minute >= s or minute < e
        day = now if minute >= s else datetime.fromtimestamp(now.timestamp() - 86400)
    if inside and q["days"]:
        inside = day.strftime("%a").lower()[:3] in q["days"]
    return inside


_held = []
_held_lock = threading.Lock()
_last_sent = {}
_suppressed = defaultdict(int)
_rl_lock = threading.Lock()


REMIND = {}
_remind_lock = threading.Lock()
# Ongoing conditions: alert once, then remind at most every N hours (True = remind_hours setting)
REMIND_DEFAULTS = {"disk": True, "clog": True, "life": True, "age": 24 * 30, "smart-fail": 12, "nvme": 12,
                   "backup": True, "ups-rb": 24 * 7, "ups-test": 24 * 7, "ups-age": 24 * 30, "ups-charge": True,
                   "bios-age": 24 * 90, "hw-inventory": 24 * 3650, "cert": True, "disktemp": 6, "vbat": 24 * 7,
                   "cleanup": True, "growth": True, "bigsize": True}


def alert(key, category, severity, subject, body, buttons=None, remind=None):
    """Central gate: severity filter, cooldown, quiet hours, then deliver.

    remind: for ongoing conditions (disk full, battery old ...). The alert is sent once, then at most
    every `remind` hours (or CFG remind_hours if remind=True), remembered across restarts."""
    if SEV.get(severity, 0) == 0:
        return
    now = time.time()
    if remind is None and isinstance(key, tuple) and key:
        remind = REMIND_DEFAULTS.get(key[0])
    if remind:
        hours = CFG["remind_hours"] if remind is True else float(remind)
        k = json.dumps(key, default=str)
        with _remind_lock:
            if now - REMIND.get(k, 0) < hours * 3600:
                return
            REMIND[k] = now
        save_state(remind=dict(REMIND))
    with _rl_lock:
        if now - _last_sent.get(key, 0) < CFG["cooldown"]:
            _suppressed[key] += 1
            log.info("cooldown, suppressed: %s", subject)
            return
        _last_sent[key] = now
        n = _suppressed.pop(key, 0)
    if n:
        body += f"\n\n({n} similar alert(s) suppressed during cooldown)"
    icon = CAT_ICON.get(category, SEV_ICON[severity])
    subject = f"{icon} {subject}"
    if severity == "critical":
        subject = f"CRITICAL: {subject}"

    if in_quiet_hours() and SEV[severity] < SEV[CFG["quiet"]["allow"]]:
        log.info("quiet hours, holding: %s", subject)
        if CFG["quiet"]["digest"]:
            with _held_lock:
                _held.append((datetime.now().strftime("%H:%M"), severity, subject))
        return
    threading.Thread(target=deliver, args=(subject, body, severity, buttons), daemon=True).start()


def digest_loop():
    was_quiet = in_quiet_hours()
    while True:
        time.sleep(60)
        q = in_quiet_hours()
        if was_quiet and not q:
            with _held_lock:
                items, _held[:] = _held[:], []
            if items:
                lines = [f"{t}  {sev:<8} {subj}" for t, sev, subj in items[:80]]
                if len(items) > 80:
                    lines.append(f"… and {len(items) - 80} more")
                deliver(f"🌙 Quiet-hours digest: {len(items)} alert(s)",
                        "Held back while quiet hours were on:\n\n" + "\n".join(lines), "info")
        was_quiet = q


# =========================================================================== rules
def wanted(name, labels):
    labels = labels or {}
    flag = str(labels.get("notifyarr.enable", "")).lower()
    if flag in ("false", "0", "no"):
        return False
    if flag in ("true", "1", "yes"):
        return True
    if CFG["include"] and name not in CFG["include"]:
        return False
    return name not in CFG["exclude"]


def match_line(source, line, extra_ignore=None):
    """Return the highest-severity rule matching a line, or None."""
    if extra_ignore and extra_ignore.search(line):
        return None
    for ig in CFG["ignore"]:
        if (not ig["sources"] or source in ig["sources"]) and ig["re"].search(line):
            return None
    best = None
    for r in CFG["rules"]:
        if r["sources"] and source not in r["sources"]:
            continue
        if source in r["exclude_sources"]:
            continue
        if r["re"].search(line) and (best is None or SEV[r["severity"]] > SEV[best["severity"]]):
            best = r
    return best


class LineBatcher:
    """Collects matching lines per (source, rule) for a few seconds, then sends one alert."""

    def __init__(self, source, kind="container"):
        self.source, self.kind = source, kind
        self.pending = {}
        self.lock = threading.Lock()

    def add(self, rule, line):
        with self.lock:
            entry = self.pending.get(rule["name"])
            if entry is None:
                entry = self.pending[rule["name"]] = (rule, [])
                t = threading.Timer(CFG["batch_seconds"], self.flush, args=(rule["name"],))
                t.daemon = True
                t.start()
            entry[1].append(line[:500])

    def flush(self, rname):
        with self.lock:
            rule, lines = self.pending.pop(rname, (None, []))
        if not lines:
            return
        shown = lines[: CFG["max_lines"]]
        label = "Container" if self.kind == "container" else "Source"
        body = f"{label}: {self.source}\nRule: {rule['name']}\n"
        if CFG["include_log_lines"]:
            body += "\n" + "\n".join(shown)
            if len(lines) > len(shown):
                body += f"\n… and {len(lines) - len(shown)} more line(s)"
        else:
            body += f"{len(lines)} matching line(s). Log text is not sent (privacy.include_log_lines = false)."
        alert(("log", self.source, rname), rule["category"], rule["severity"],
              f"{self.source}: {rule['name']}", body)


def handle_match(source, rule, line, batcher):
    if rule["ip"] == "any":
        batcher.add(rule, line)
        return
    untrusted = [ip for ip in extract_ips(line) if not TRUST.match(ip)]
    if rule["ip"] == "new":
        untrusted = [ip for ip in untrusted if TRUST.first_seen(ip)]
    for ip in untrusted:
        net24 = ipaddress.ip_network(f"{ip}/24" if ":" not in ip else f"{ip}/64", strict=False)
        alert(("ip", source, rule["name"], ip), rule["category"], rule["severity"],
              f"{source}: {rule['name']} from {ip}",
              f"Source: {source}\nRule: {rule['name']}\nIP: {ip} (not in your trusted list)\n\n{line[:800]}"
              f"\n\nIf this is you, tap Trust below or send /trust {ip}",
              buttons=[(f"Trust {ip}", f"trust:{ip}"), (f"Trust {net24}", f"trust:{net24}")])


# =========================================================================== container logs
SELF_ID = socket.gethostname()
_log_threads = set()
_log_lock = threading.Lock()


def iter_log_lines(resp, tty):
    buf = b""
    while True:
        if tty:
            chunk = resp.read1(65536)
            if not chunk:
                break
            buf += chunk
        else:
            header = resp.read(8)
            if len(header) < 8:
                break
            size = int.from_bytes(header[4:8], "big")
            buf += resp.read(size) if size else b""
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode("utf-8", "replace").rstrip("\r")
    if buf:
        yield buf.decode("utf-8", "replace")


def watch_container_logs(cid, name, tty, labels):
    ign = labels.get("notifyarr.ignore")
    extra_ignore = re.compile(ign) if ign else None
    batcher = LineBatcher(name)
    try:
        conn, resp = docker_stream(f"/containers/{cid}/logs?follow=1&stdout=1&stderr=1&tail=0")
    except Exception as e:  # noqa: BLE001
        log.warning("cannot follow logs of %s: %s", name, e)
        with _log_lock:
            _log_threads.discard(cid)
        return
    log.info("following logs of %s", name)
    try:
        for line in iter_log_lines(resp, tty):
            if not line.strip():
                continue
            rule = match_line(name, line, extra_ignore)
            if rule:
                handle_match(name, rule, line, batcher)
    except Exception as e:  # noqa: BLE001
        log.debug("log stream for %s ended: %s", name, e)
    finally:
        conn.close()
        with _log_lock:
            _log_threads.discard(cid)


def start_log_watch(cid):
    if not CFG["watch_logs"] or cid.startswith(SELF_ID):
        return
    with _log_lock:
        if cid in _log_threads:
            return
        _log_threads.add(cid)
    try:
        info = docker_get(f"/containers/{cid}/json")
        name = info["Name"].lstrip("/")
        labels = info["Config"].get("Labels") or {}
        if not wanted(name, labels):
            raise LookupError("not wanted")
    except Exception as e:  # noqa: BLE001
        if not isinstance(e, LookupError):
            log.warning("inspect %s failed: %s", cid[:12], e)
        with _log_lock:
            _log_threads.discard(cid)
        return
    threading.Thread(target=watch_container_logs,
                     args=(cid, name, bool(info["Config"].get("Tty")), labels), daemon=True).start()


# =========================================================================== docker events
_restarts = defaultdict(deque)
_unhealthy = set()

EXIT_CODES = {
    "1": "application error", "2": "misuse / bad arguments", "125": "docker run failed",
    "126": "command not executable", "127": "command not found", "130": "interrupted (SIGINT)",
    "134": "aborted (SIGABRT)", "137": "killed (SIGKILL; often OOM or docker kill)",
    "139": "segmentation fault", "143": "terminated (SIGTERM)",
}


def last_log_lines(cid, n=15):
    try:
        info = docker_get(f"/containers/{cid}/json")
        c, r = docker_stream(f"/containers/{cid}/logs?stdout=1&stderr=1&tail={n}", timeout=10)
        lines = list(iter_log_lines(r, bool(info["Config"].get("Tty"))))
        c.close()
        return "\n".join(l[:300] for l in lines[-n:])[-2500:]
    except Exception:  # noqa: BLE001
        return ""


def handle_event(ev):
    if ev.get("Type") != "container":
        return
    if not CFG["events_enabled"] and ev.get("Action") != "start":
        return
    action = ev.get("Action", "")
    attrs = (ev.get("Actor") or {}).get("Attributes") or {}
    cid = (ev.get("Actor") or {}).get("ID") or ev.get("id", "")
    name = attrs.get("name", cid[:12])
    if cid.startswith(SELF_ID) or not wanted(name, attrs):
        return
    image = attrs.get("image", "?")
    E = CFG["ev"]

    if action == "start":
        start_log_watch(cid)
        q = _restarts[name]
        now = time.time()
        q.append(now)
        while q and now - q[0] > CFG["restart_loop_window"]:
            q.popleft()
        if len(q) >= CFG["restart_loop_count"]:
            alert(("restart", name), "restart_loop", E["restart_loop"], f"{name} is restart-looping",
                  f"Container: {name}\nImage: {image}\nStarted {len(q)} times in the last "
                  f"{CFG['restart_loop_window'] // 60} min.")

    elif action == "die":
        code = attrs.get("exitCode", "?")
        sev = E["clean_exit"] if code == "0" else E["crash"]
        if SEV.get(sev, 0) == 0:
            return
        body = f"Container: {name}\nImage: {image}\nExit code: {code} ({EXIT_CODES.get(code, 'error')})"
        tail = last_log_lines(cid) if CFG["include_log_lines"] else ""
        if tail:
            body += "\n\nLast log lines:\n" + tail
        alert(("die", name), "crash", sev, f"{name} stopped (exit {code})", body)

    elif action == "oom":
        alert(("oom", name), "oom", E["oom"], f"{name} ran out of memory",
              f"Container: {name}\nImage: {image}\nKilled for exceeding its memory limit.")

    elif action.startswith("health_status"):
        status = action.split(":", 1)[-1].strip()
        if status == "unhealthy":
            _unhealthy.add(name)
            out = ""
            try:
                logs = (docker_get(f"/containers/{cid}/json")["State"].get("Health") or {}).get("Log") or []
                if logs:
                    out = (logs[-1].get("Output") or "").strip()[:800]
            except Exception:  # noqa: BLE001
                pass
            body = f"Container: {name}\nImage: {image}\nHealthcheck is failing."
            if out:
                body += f"\n\nLast healthcheck output:\n{out}"
            alert(("health", name), "unhealthy", E["unhealthy"], f"{name} is unhealthy", body)
        elif status == "healthy" and name in _unhealthy:
            _unhealthy.discard(name)
            alert(("recovered", name, time.time()), "recovered", E["recovered"],
                  f"{name} is healthy again", f"Container: {name}\nImage: {image}")


def watch_events():
    filters = urllib.parse.quote(json.dumps({"type": ["container"]}))
    while True:
        try:
            conn, resp = docker_stream(f"/events?filters={filters}")
            log.info("connected to Docker event stream")
            while True:
                line = resp.readline()
                if not line:
                    break
                if line.strip():
                    try:
                        handle_event(json.loads(line))
                    except Exception:  # noqa: BLE001
                        log.exception("error handling event")
            conn.close()
        except Exception as e:  # noqa: BLE001
            log.warning("event stream error: %s; reconnecting in 5s", e)
        time.sleep(5)


# =========================================================================== host: syslog
def follow_file(path):
    """tail -F: yields new lines, survives rotation/truncation."""
    f, ino = None, None
    while True:
        if f is None:
            try:
                f = open(path, "r", errors="replace")
                st = os.fstat(f.fileno())
                ino = st.st_ino
                if not getattr(follow_file, "_started_" + path, False):
                    f.seek(0, os.SEEK_END)  # first open: only new lines
                    setattr(follow_file, "_started_" + path, True)
                log.info("following %s", path)
            except OSError as e:
                log.warning("cannot open %s: %s; retrying in 30s", path, e)
                time.sleep(30)
                continue
        line = f.readline()
        if line:
            yield line.rstrip("\n")
            continue
        time.sleep(1)
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():
                f.close()
                f = None
        except OSError:
            pass


def watch_syslog():
    path, name = CFG["syslog"], CFG["syslog_name"]
    batcher = LineBatcher(name, kind="host")
    for line in follow_file(path):
        rule = match_line(name, line)
        if rule:
            handle_match(name, rule, line, batcher)


# =========================================================================== host: unraid notifications
def parse_notify(path):
    d = {}
    with open(path, errors="replace") as f:
        for line in f:
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip().strip('"')
    return d


def watch_unraid_notifications():
    base = CFG["unraid_notify"]
    dirs = [os.path.join(base, "unread"), os.path.join(base, "archive")]
    seen = set()
    first = True
    while True:
        for d in dirs:
            try:
                files = [f for f in os.listdir(d) if f.endswith(".notify")]
            except OSError:
                continue
            for fn in files:
                if fn in seen:
                    continue
                seen.add(fn)
                if first:
                    continue
                try:
                    n = parse_notify(os.path.join(d, fn))
                except OSError:
                    continue
                sev = CFG["unraid_map"].get(n.get("importance", "normal"), "info")
                subject = n.get("subject") or n.get("event") or "Unraid notification"
                body = "\n".join(x for x in (n.get("event"), n.get("description")) if x)
                if n.get("content"):
                    body += "\n\n" + n["content"]
                if n.get("description"):
                    rule = match_line("unraid-notifications", subject + " " + n["description"])
                    if rule is None and any(ig["re"].search(subject) for ig in CFG["ignore"]):
                        continue
                alert(("unraid", fn), "unraid", sev, f"Unraid: {subject}", body or subject)
        first = False
        time.sleep(15)


# =========================================================================== crowdsec
def in_trusted(value):
    return TRUST.match(value)


def crowdsec_loop():
    cs = CFG["cs"]
    if not cs["key"]:
        log.warning("crowdsec enabled but CROWDSEC_BOUNCER_KEY is not set; skipping")
        return
    startup = True
    while True:
        try:
            req = urllib.request.Request(
                f"{cs['url']}/v1/decisions/stream?startup={'true' if startup else 'false'}",
                headers={"X-Api-Key": cs["key"], "User-Agent": "notifyarr"},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read() or b"{}")
            handle_decisions(data.get("new") or [], startup)
            startup = False
        except Exception as e:  # noqa: BLE001
            log.warning("crowdsec poll failed: %s", e)
        time.sleep(cs["poll"])


def handle_decisions(new, startup):
    cs = CFG["cs"]
    bans, geos = [], []
    for d in new:
        value, scope = d.get("value", ""), d.get("scope", "")
        scenario, origin = d.get("scenario", ""), d.get("origin", "")
        desc = f"{scope} {value}  [{d.get('type', 'ban')}, {d.get('duration', '?')}]  {scenario} ({origin})"
        trusted = in_trusted(value) if scope.lower() in ("ip", "range") else None
        if trusted:  # always checked, even for the startup snapshot and blocklists
            alert(("faulty", value), "faulty_ban", cs["faulty"], f"Trusted address banned: {value}",
                  f"CrowdSec banned {value}, which is inside your trusted range {trusted}.\n\n"
                  f"{desc}\n\nIf this is a false positive, remove it on the CrowdSec host with:\n"
                  f"  cscli decisions delete --ip {value}\n"
                  f"and consider whitelisting it (crowdsecurity/whitelists).")
            continue
        if startup or origin not in cs["origins"]:
            continue
        if any(p.search(scenario) for p in cs["ignore_scenarios"]):
            continue
        if scope.lower() == "country" or cs["geoblock_scenarios"].search(scenario):
            geos.append(desc)
        else:
            bans.append(desc)
    for kind, items, sev, title in (("ban", bans, cs["ban"], "CrowdSec banned"),
                                    ("geoblock", geos, cs["geoblock"], "CrowdSec geoblocked")):
        if items:
            body = "\n".join(items[:30]) + (f"\n… and {len(items) - 30} more" if len(items) > 30 else "")
            alert(("cs", kind, time.time()), kind, sev, f"{title} {len(items)} address(es)", body)


# =========================================================================== telegram commands
HELP = ("Commands:\n"
        "/trust <ip or range> [note]  add to the trusted list\n"
        "/untrust <ip or range>  remove from the trusted list\n"
        "/trusted  show trusted IPs and ranges\n"
        "/status  containers, quiet hours, alerts today\n"
        "/hardware  board, BIOS and disk firmware, with update steps")


def tg_reply(text):
    try:
        data = {"chat_id": CFG["tg_chat"], "text": text[:4000]}
        if CFG["tg_thread"]:
            data["message_thread_id"] = CFG["tg_thread"]
        tg_api("sendMessage", data)
    except Exception as e:  # noqa: BLE001
        log.warning("telegram reply failed: %s", e)


def tg_command(text):
    parts = text.strip().split()
    cmd = parts[0].split("@")[0].lower() if parts else ""
    arg = parts[1] if len(parts) > 1 else ""
    if cmd == "/trust" and arg:
        n = TRUST.add(arg, " ".join(parts[2:]) or "via Telegram")
        return f"✅ Trusted {n}. It won't trigger IP alerts any more." if n else f"❌ '{arg}' is not a valid IP or range."
    if cmd == "/untrust" and arg:
        return f"🗑️ Removed {arg}." if TRUST.remove(arg) else (
            f"{arg} isn't in trusted_ips.txt (entries in config.toml must be removed there).")
    if cmd == "/trusted":
        st, dyn = TRUST.listing()
        return ("From config.toml:\n" + ("\n".join(st) or "(none)") +
                "\n\nAdded (trusted_ips.txt):\n" + ("\n".join(dyn) or "(none)"))
    if cmd == "/status":
        return status_text()[0]
    if cmd == "/hardware":
        return hardware_report()[0]
    return HELP


def telegram_bot_loop():
    offset = None
    chat = str(CFG["tg_chat"])
    while True:
        try:
            data = {"timeout": 50, "allowed_updates": json.dumps(["message", "callback_query"])}
            if offset:
                data["offset"] = offset
            res = tg_api("getUpdates", data, timeout=60)
            for u in res.get("result", []):
                offset = u["update_id"] + 1
                if "callback_query" in u:
                    cq = u["callback_query"]
                    if str(cq.get("message", {}).get("chat", {}).get("id")) != chat:
                        continue
                    d = cq.get("data", "")
                    reply = tg_command("/trust " + d[6:] + " via button") if d.startswith("trust:") else "?"
                    try:
                        tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": reply[:190]})
                    except Exception:  # noqa: BLE001
                        pass
                    tg_reply(reply)
                    continue
                msg = u.get("message") or {}
                if str(msg.get("chat", {}).get("id")) != chat:
                    continue  # only obey the configured chat
                if (msg.get("text") or "").startswith("/"):
                    tg_reply(tg_command(msg["text"]))
        except Exception as e:  # noqa: BLE001
            log.warning("telegram polling failed: %s", e)
            time.sleep(15)


# =========================================================================== disks
POOL_SKIP = {"user", "user0", "disks", "remotes", "addons", "rootshare"}


def storage_paths():
    d = CFG["disks"]
    paths = {}
    if d["array"]:
        paths["Array"] = d["array"]
    if d["auto_pools"]:
        try:
            for n in sorted(os.listdir(d["mnt"])):
                full = os.path.join(d["mnt"], n)
                if n in POOL_SKIP or n.startswith("disk") or not os.path.isdir(full):
                    continue
                if os.path.ismount(full) or os.statvfs(full).f_fsid != os.statvfs(d["mnt"]).f_fsid:
                    paths[f"Pool {n}"] = full
        except OSError:
            pass
    if d["docker_dir"]:
        paths["docker.img"] = d["docker_dir"]
    paths.update(d["paths"])
    return paths


def container_log_sizes():
    """Size of each container's Docker log file (json-file driver)."""
    d = CFG["disks"]
    out = {}
    if not d["docker_dir"]:
        return out
    try:
        for c in docker_get("/containers/json"):
            name = c["Names"][0].lstrip("/")
            f = os.path.join(d["docker_dir"], c["Id"], f"{c['Id']}-json.log")
            try:
                out[name] = os.path.getsize(f)
            except OSError:
                pass
    except Exception:  # noqa: BLE001
        pass
    return out


def disk_loop():
    d = CFG["disks"]
    while True:
        if d["log_dir"]:
            try:
                st = os.statvfs(d["log_dir"])
                total = st.f_blocks * st.f_frsize
                pct = 100 * (1 - st.f_bavail * st.f_frsize / total) if total else 0
                if pct >= d["log_warn"]:
                    sev = "critical" if pct >= d["crit"] else "warning"
                    alert(("disk", "log", sev), "disk", sev, f"Unraid log space is {pct:.0f}% full",
                          f"/var/log is a small RAM disk ({total / 1e6:.0f} MB). When it fills, the web UI and "
                          "Docker can misbehave. Find what is spamming the syslog (Tools > System Log).")
            except OSError as e:
                log.warning("log dir check failed: %s", e)
        if d["container_log_mb"] > 0:
            for name, size in container_log_sizes().items():
                if wanted(name, None) and size / 1048576 >= d["container_log_mb"]:
                    alert(("clog", name), "disk", "warning", f"{name}: log file is {size / 1048576:.0f} MB",
                          f"Docker's log file for {name} is {size / 1048576:.0f} MB and lives inside docker.img.\n"
                          "Limit it with --log-opt max-size=50m (Unraid: Settings > Docker > container log rotation).")
        for label, path in storage_paths().items():
            try:
                st = os.statvfs(path)
            except OSError as e:
                log.warning("disk check %s (%s) failed: %s", label, path, e)
                continue
            total = st.f_blocks * st.f_frsize
            if not total:
                continue
            free = st.f_bavail * st.f_frsize
            pct = 100 * (1 - free / total)
            sev = "critical" if pct >= d["crit"] else "warning" if pct >= d["warn"] else None
            if sev:
                alert(("disk", label, sev), "disk", sev, f"{label} is {pct:.0f}% full",
                      f"{label} ({path}): {pct:.1f}% used, {free / 1e9:.1f} GB free of {total / 1e9:.0f} GB.")
        time.sleep(d["every"])


def disk_summary():
    out = []
    for label, path in storage_paths().items():
        try:
            st = os.statvfs(path)
            total = st.f_blocks * st.f_frsize
            if total:
                out.append(f"{label} {100 * (1 - st.f_bavail * st.f_frsize / total):.0f}%")
        except OSError:
            pass
    return ", ".join(out)


# =========================================================================== image updates
def registry_digest(image):
    """Return the remote manifest digest for an image reference like lscr.io/linuxserver/sonarr:latest."""
    ref, tag = image, "latest"
    if "@" in ref:
        return None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, ref.split("/", 1)[1]
    else:
        registry, repo = "registry-1.docker.io", ref if "/" in ref else f"library/{ref}"
    if registry == "docker.io":
        registry = "registry-1.docker.io"
    url = f"https://{registry}/v2/{repo}/manifests/{tag}"
    accept = ", ".join([
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ])
    headers = {"Accept": accept, "User-Agent": "notifyarr"}
    for _ in range(2):
        req = urllib.request.Request(url, method="HEAD", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.headers.get("Docker-Content-Digest")
        except urllib.error.HTTPError as e:
            auth = e.headers.get("WWW-Authenticate", "")
            if e.code != 401 or not auth.lower().startswith("bearer"):
                return None
            params = dict(re.findall(r'(\w+)="([^"]*)"', auth))
            q = urllib.parse.urlencode({k: v for k, v in params.items() if k in ("service", "scope")})
            with urllib.request.urlopen(f"{params['realm']}?{q}", timeout=20) as r:
                tok = json.loads(r.read())
            headers["Authorization"] = "Bearer " + (tok.get("token") or tok.get("access_token", ""))
    return None


def updates_loop():
    u = CFG["updates"]
    notified = {}
    time.sleep(120)
    while True:
        try:
            outdated = []
            for c in docker_get("/containers/json"):
                name = c["Names"][0].lstrip("/")
                if name in u["skip"] or not wanted(name, c.get("Labels")):
                    continue
                image = c.get("Image", "")
                if image.startswith("sha256:"):
                    continue
                try:
                    local = docker_get(f"/images/{urllib.parse.quote(c['ImageID'], safe='')}/json")
                    repo_digests = [d.split("@", 1)[1] for d in local.get("RepoDigests") or []]
                    remote = registry_digest(image)
                except Exception as e:  # noqa: BLE001
                    log.debug("update check %s failed: %s", name, e)
                    continue
                if remote and repo_digests and remote not in repo_digests and notified.get(name) != remote:
                    notified[name] = remote
                    outdated.append(f"{name}  ({image})")
            if outdated:
                alert(("updates", time.time()), "host", u["severity"],
                      f"{len(outdated)} container update(s) available",
                      "New images are available for:\n\n" + "\n".join(outdated))
        except Exception as e:  # noqa: BLE001
            log.warning("update check failed: %s", e)
        time.sleep(u["every"])


# =========================================================================== certificates
def cert_days_left(target):
    host, _, port = target.partition(":")
    ctx = ssl.create_default_context()
    with socket.create_connection((host, int(port or 443)), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cert = s.getpeercert()
    exp = ssl.cert_time_to_seconds(cert["notAfter"])
    return (exp - time.time()) / 86400


def certs_loop():
    c = CFG["certs"]
    while True:
        for h in c["hosts"]:
            try:
                days = cert_days_left(h)
            except ssl.SSLCertVerificationError as e:
                alert(("cert", h, "invalid"), "security", "critical", f"SSL certificate invalid: {h}", str(e))
                continue
            except Exception as e:  # noqa: BLE001
                log.warning("cert check %s failed: %s", h, e)
                continue
            sev = "critical" if days <= c["crit"] else "warning" if days <= c["warn"] else None
            if sev:
                alert(("cert", h, sev), "security", sev, f"SSL certificate for {h} expires in {days:.0f} day(s)",
                      f"{h}: certificate expires in {days:.1f} days. Check your reverse proxy / ACME renewals.")
        time.sleep(c["every"])


# =========================================================================== daily summary
def status_text():
    try:
        cs = docker_get("/containers/json?all=1")
    except Exception as e:  # noqa: BLE001
        return f"Docker API unavailable: {e}", False
    cs = [c for c in cs if wanted(c["Names"][0].lstrip("/"), c.get("Labels"))]
    running = [c for c in cs if c["State"] == "running"]
    unhealthy = [c["Names"][0].lstrip("/") for c in running if "(unhealthy)" in c.get("Status", "")]
    stopped = [c["Names"][0].lstrip("/") for c in cs if c["State"] == "exited"
               and not c.get("Status", "").startswith("Exited (0)")]
    lines = [f"Containers running: {len(running)}/{len(cs)}"]
    lines.append("Unhealthy: " + (", ".join(unhealthy) or "none"))
    lines.append("Stopped with errors: " + (", ".join(stopped) or "none"))
    ds = disk_summary()
    if ds:
        lines.append("Disks: " + ds)
    lines.append(f"Alerts in last 24h: {STATS['critical']} critical, {STATS['warning']} warning, {STATS['info']} info")
    lines.append("Quiet hours: " + ("ON now" if in_quiet_hours() else "off now"))
    return "\n".join(lines), not unhealthy and not stopped


def heartbeat_loop():
    target = CFG["heartbeat"]["time"]
    last_day = None
    while True:
        now = datetime.now()
        if now.hour * 60 + now.minute == target and last_day != now.date():
            last_day = now.date()
            text, ok = status_text()
            deliver(("✅ Daily check: all OK" if ok else "📋 Daily check: needs attention"), text, "info")
            STATS.clear()
        time.sleep(20)


# =========================================================================== unraid tasks / array
def parse_ini(path):
    """Parse Unraid's emhttp .ini files (key="value", optional ["section"] headers)."""
    top, sections, cur = {}, {}, None
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                cur = sections.setdefault(line[1:-1].strip('"'), {})
            elif "=" in line:
                k, v = line.split("=", 1)
                (cur if cur is not None else top)[k.strip()] = v.strip().strip('"')
    return top, sections


def resync_kind(action):
    a = (action or "").lower()
    if a.startswith("recon"):
        return "rebuild"
    if a.startswith("clear"):
        return "clear"
    if a.startswith("check") and a.strip() != "check":
        return "parity_check"
    return "read_check"


KIND_LABEL = {"parity_check": "Parity check", "read_check": "Read check",
              "rebuild": "Parity sync / disk rebuild", "clear": "Disk clear"}


def fmt_dur(sec):
    h, m = divmod(int(sec) // 60, 60)
    return f"{h}h {m:02d}m"


def unraid_tasks_loop():
    t = CFG["tasks"]
    var_ini = os.path.join(t["emhttp"], "var.ini")
    disks_ini = os.path.join(t["emhttp"], "disks.ini")
    st = {"resync": None, "mover": None, "md_state": None, "disk_status": {}, "disk_errors": {}}
    first = True
    while True:
        now = time.time()
        # ---- parity / read check / rebuild
        try:
            v, _ = parse_ini(var_ini)
        except OSError as e:
            log.warning("cannot read %s: %s", var_ini, e)
            v = None
        if v is not None:
            active = int(v.get("mdResync", "0") or 0) > 0
            kind = resync_kind(v.get("mdResyncAction"))
            pos = int(v.get("mdResyncPos", "0") or 0)
            size = int(v.get("mdResyncSize", "0") or 0) or int(v.get("mdResync", "0") or 0)
            paused = v.get("mdResyncDt", "1") == "0"
            r = st["resync"]
            if active and r is None:
                r = st["resync"] = {"kind": kind, "start": now, "pos": pos, "moved": now,
                                    "long": False, "stalled": False}
                if not first:
                    alert(("task", kind, "start", now), "unraid", t["start_severity"],
                          f"{KIND_LABEL[kind]} started", v.get("mdResyncAction", ""))
            elif active and r:
                pct = 100 * pos / size if size else 0
                if pos != r["pos"]:
                    r["pos"], r["moved"], r["stalled"] = pos, now, False
                elapsed = now - r["start"]
                limit = t["max_hours"].get(r["kind"], 24) * 3600
                if elapsed > limit and not r["long"]:
                    r["long"] = True
                    alert(("task", r["kind"], "long"), "unraid", "warning",
                          f"{KIND_LABEL[r['kind']]} is taking too long",
                          f"Running for {fmt_dur(elapsed)} (limit {fmt_dur(limit)}), {pct:.1f}% done.\n"
                          "A slow check can mean a failing disk, a bad cable, or heavy disk activity.")
                if (not paused and now - r["moved"] > t["stall_minutes"] * 60 and not r["stalled"]):
                    r["stalled"] = True
                    alert(("task", r["kind"], "stall"), "unraid", "critical",
                          f"{KIND_LABEL[r['kind']]} looks stuck",
                          f"No progress for {t['stall_minutes']} min at {pct:.1f}%.\n"
                          "Check the syslog and disk health (SMART) on the Main tab.")
            elif not active and r is not None:
                st["resync"] = None
                errs = int(v.get("sbSyncErrs", "0") or 0)
                sev = "critical" if errs else t["finish_severity"]
                alert(("task", r["kind"], "done", now), "unraid", sev,
                      f"{KIND_LABEL[r['kind']]} finished" + (f" with {errs} error(s)" if errs else ""),
                      f"Duration: {fmt_dur(now - r['start'])}\nSync errors: {errs}"
                      + ("\n(It may have been cancelled.)" if v.get("sbSyncExit", "0") not in ("0", "") else ""))
            # ---- array state
            md = v.get("mdState")
            if md and st["md_state"] and md != st["md_state"] and md != "STARTED":
                alert(("array", md), "unraid", "warning", f"Array state is {md}",
                      f"The array changed from {st['md_state']} to {md}.")
            st["md_state"] = md or st["md_state"]
            dis = int(v.get("mdNumDisabled", "0") or 0)
            if dis:
                alert(("array", "disabled"), "disk", "critical", f"{dis} array disk(s) disabled",
                      "One or more disks are disabled (red X). Data is being emulated until it is rebuilt.")
        # ---- disks
        try:
            _, disks = parse_ini(disks_ini)
        except OSError:
            disks = {}
        for dname, d in disks.items():
            status = d.get("status", "")
            if status.startswith("DISK_NP") or not status:
                continue
            prev = st["disk_status"].get(dname)
            if status != "DISK_OK" and status != prev:
                alert(("diskstatus", dname, status), "disk", "critical", f"Disk {dname} status: {status}",
                      f"Device: {d.get('id', '?')}\nStatus changed from {prev or 'unknown'} to {status}.")
            st["disk_status"][dname] = status
            errs = int(d.get("numErrors", "0") or 0)
            perr = st["disk_errors"].get(dname)
            if perr is not None and errs > perr:
                alert(("diskerr", dname, errs), "disk", "critical", f"Disk {dname} has {errs} read/write error(s)",
                      f"Device: {d.get('id', '?')}\nErrors went from {perr} to {errs}. Check SMART and cabling.")
            st["disk_errors"][dname] = errs
            temp = d.get("temp", "*")
            if temp.isdigit() and int(temp) >= t["disk_temp_critical"]:
                alert(("disktemp", dname), "disk", "critical", f"Disk {dname} is {temp}°C",
                      f"Device: {d.get('id', '?')}\nAt or above {t['disk_temp_critical']}°C.")
        # ---- mover
        running = os.path.exists(t["mover_pid"])
        m = st["mover"]
        if running and m is None:
            st["mover"] = {"start": now, "long": False}
        elif running and m and not m["long"] and now - m["start"] > t["max_hours"]["mover"] * 3600:
            m["long"] = True
            alert(("task", "mover", "long"), "unraid", "warning", "Mover is taking too long",
                  f"Mover has been running for {fmt_dur(now - m['start'])} "
                  f"(limit {t['max_hours']['mover']}h). Cache may fill up.")
        elif not running and m is not None:
            st["mover"] = None
            alert(("task", "mover", "done", now), "unraid", t["mover_finish_severity"], "Mover finished",
                  f"Duration: {fmt_dur(now - m['start'])}")
        first = False
        time.sleep(t["every"])


# =========================================================================== wireguard
def wireguard_loop():
    w = CFG["wg"]
    down = set()
    have_wg = os.path.exists("/usr/bin/wg") or os.path.exists("/sbin/wg") or os.path.exists("/usr/sbin/wg")
    while True:
        problems = {}
        for tgt in w["ping"]:
            name, _, host = tgt.partition("=") if "=" in tgt else (tgt, "", tgt)
            ok = subprocess.run(["ping", "-c", "3", "-W", "3", host], capture_output=True).returncode == 0
            if not ok:
                problems[f"ping:{name}"] = f"Tunnel {name}: {host} is not answering ping."
        if w["handshake"] and have_wg:
            try:
                out = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True,
                                     timeout=10).stdout
            except Exception as e:  # noqa: BLE001
                out = ""
                log.warning("wg show failed: %s", e)
            for line in out.splitlines():
                f = line.split("\t")
                if len(f) != 9:
                    continue  # interface line
                iface, pub, endpoint, allowed, hs = f[0], f[1], f[3], f[4], int(f[5] or 0)
                label = next((n for n, key in w["peers"].items() if pub.startswith(key) or any(a.startswith(key + "/") for a in allowed.split(","))), None)
                if label is None:
                    continue
                age = time.time() - hs if hs else None
                if age is None or age > w["max_handshake_minutes"] * 60:
                    seen = "never" if age is None else f"{fmt_dur(age)} ago"
                    problems[f"hs:{label}"] = (f"Tunnel {label} ({iface}, {allowed}): last handshake {seen}"
                                               f" (limit {w['max_handshake_minutes']} min). Endpoint {endpoint}.")
        for key, msg in problems.items():
            if key not in down:
                down.add(key)
                alert(("wg", key), "host", w["severity"], "WireGuard tunnel down", msg)
        for key in list(down - set(problems)):
            down.discard(key)
            alert(("wg-up", key, time.time()), "recovered", "info", "WireGuard tunnel back up",
                  key.split(":", 1)[1] + " is working again.")
        time.sleep(w["every"])


# =========================================================================== per-container resources
RES_KEYS = ("cpu_percent", "memory_mb", "memory_percent", "disk_io_mbps", "disk_size_gb")
RES_LABEL = {"cpu_percent": ("CPU", "%"), "memory_mb": ("RAM", " MB"), "memory_percent": ("RAM", "% of limit"),
             "disk_io_mbps": ("Disk I/O", " MB/s"), "disk_size_gb": ("Container disk", " GB")}


def res_limits(name, labels):
    r = CFG["res"]
    lim = dict(r["defaults"])
    lim.update(r["per"].get(name, {}))
    for k in RES_KEYS + ("for_minutes", "severity"):
        v = (labels or {}).get(f"notifyarr.{k}")
        if v not in (None, ""):
            lim[k] = v
    return lim


def sample_stats(cid):
    st = docker_get(f"/containers/{cid}/stats?stream=false", timeout=30)
    cpu, pre = st.get("cpu_stats", {}), st.get("precpu_stats", {})
    cd = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    sd = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    cpu_pct = (cd / sd) * ncpu * 100 if sd > 0 and cd >= 0 else 0.0
    mem = st.get("memory_stats", {})
    used = mem.get("usage", 0) - (mem.get("stats", {}).get("inactive_file")
                                  or mem.get("stats", {}).get("total_inactive_file") or 0)
    limit = mem.get("limit", 0)
    io = 0
    for e in (st.get("blkio_stats", {}).get("io_service_bytes_recursive") or []):
        if str(e.get("op", "")).lower() in ("read", "write"):
            io += e.get("value", 0)
    return {"cpu": cpu_pct, "mem": max(used, 0), "limit": limit, "io": io}


def resources_loop():
    r = CFG["res"]
    over = {}          # (name, key) -> first time over
    prev_io = {}
    sizes, sizes_at = {}, 0
    while True:
        try:
            cs = docker_get("/containers/json")
        except Exception as e:  # noqa: BLE001
            log.warning("resources: %s", e)
            time.sleep(r["every"])
            continue
        now = time.time()
        if now - sizes_at > r["size_every"]:
            try:
                sizes = {c["Id"]: c.get("SizeRw", 0) for c in docker_get("/containers/json?size=1", timeout=300)}
                sizes_at = now
            except Exception as e:  # noqa: BLE001
                log.warning("container size check failed: %s", e)
        for c in cs:
            name = c["Names"][0].lstrip("/")
            labels = c.get("Labels") or {}
            if c["Id"].startswith(SELF_ID) or not wanted(name, labels):
                continue
            lim = res_limits(name, labels)
            if not any(float(lim.get(k) or 0) > 0 for k in RES_KEYS):
                continue
            try:
                s = sample_stats(c["Id"])
            except Exception as e:  # noqa: BLE001
                log.debug("stats %s failed: %s", name, e)
                continue
            p = prev_io.get(c["Id"])
            prev_io[c["Id"]] = (now, s["io"])
            vals = {
                "cpu_percent": s["cpu"],
                "memory_mb": s["mem"] / 1048576,
                "memory_percent": (100 * s["mem"] / s["limit"]) if s["limit"] and s["limit"] < 2**60 else None,
                "disk_io_mbps": ((s["io"] - p[1]) / (now - p[0]) / 1048576) if p and now > p[0] else None,
                "disk_size_gb": sizes.get(c["Id"], 0) / 1e9 if sizes else None,
            }
            hold = float(lim.get("for_minutes", r["for_minutes"])) * 60
            for k in RES_KEYS:
                thr = float(lim.get(k) or 0)
                v = vals[k]
                key = (name, k)
                if thr <= 0 or v is None or v < thr:
                    if key in over and over[key] == "alerted":
                        label, unit = RES_LABEL[k]
                        alert(("res-ok", name, k, now), "recovered", "info", f"{name}: {label} back to normal",
                              f"{label} is now {v:.1f}{unit} (threshold {thr:g}{unit}).")
                    over.pop(key, None)
                    continue
                if key not in over:
                    over[key] = now
                if over[key] != "alerted" and (k == "disk_size_gb" or now - over[key] >= hold):
                    over[key] = "alerted"
                    label, unit = RES_LABEL[k]
                    alert(("res", name, k), "host", lim.get("severity", r["severity"]),
                          f"{name}: high {label} ({v:.0f}{unit})",
                          f"Container: {name}\n{label}: {v:.1f}{unit}, threshold {thr:g}{unit}"
                          + (f", for over {hold / 60:.0f} min" if k != "disk_size_gb" else "") + ".")
        time.sleep(r["every"])


# =========================================================================== reboot / internet / http checks
def host_uptime():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return None


def load_state():
    try:
        with open(CFG["state_file"]) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(**kw):
    st = load_state()
    st.update(kw)
    try:
        with open(CFG["state_file"], "w") as f:
            json.dump(st, f)
    except OSError as e:
        log.debug("state save failed: %s", e)


def check_reboot():
    """Run once at startup: did the host reboot, and was the previous shutdown clean?"""
    st = load_state()
    up = host_uptime()
    boot = time.time() - up if up is not None else None
    last_boot = st.get("boot")
    rebooted = boot is not None and last_boot is not None and abs(boot - last_boot) > 120
    if rebooted:
        last_seen = st.get("heartbeat", 0)
        clean = st.get("clean_stop", False)
        sb_clean = None
        try:
            v, _ = parse_ini(os.path.join(CFG["tasks"]["emhttp"], "var.ini"))
            sb_clean = v.get("sbClean")
        except OSError:
            pass
        if sb_clean == "no":
            clean = False
        down = f"{fmt_dur(boot - last_seen)}" if last_seen else "unknown"
        when = datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M") if last_seen else "unknown"
        if clean:
            alert(("reboot", boot), "host", CFG["reboot"]["clean"], "Server restarted",
                  f"The server was shut down cleanly and is back up.\nLast seen: {when}\nOffline for about {down}.")
        else:
            alert(("reboot", boot), "host", CFG["reboot"]["unclean"], "Server came back after an UNCLEAN shutdown",
                  f"The server went down without a clean shutdown (power cut, crash or hard reset).\n"
                  f"Last seen: {when}\nOffline for about {down}.\n\n"
                  "Unraid will usually start a parity check by itself. Check the UPS and syslog.")
    save_state(boot=boot, clean_stop=False, heartbeat=time.time())


def state_heartbeat_loop():
    while True:
        save_state(heartbeat=time.time(), clean_stop=False)
        time.sleep(60)


def internet_up():
    for host, port in CFG["net"]["targets"]:
        try:
            socket.create_connection((host, port), timeout=5).close()
            return True
        except OSError:
            continue
    return False


def internet_loop():
    n = CFG["net"]
    down_since, fails = None, 0
    while True:
        ok = internet_up()
        if not ok:
            fails += 1
            if fails >= n["fail_count"] and down_since is None:
                down_since = time.time() - n["every"] * (fails - 1)
                log.warning("internet looks down")
        else:
            fails = 0
            if down_since is not None:
                dur = time.time() - down_since
                down_since = None
                alert(("net-up", time.time()), "host", n["severity"], "Internet connection restored",
                      f"The internet was down for about {fmt_dur(dur)} "
                      f"(from {datetime.fromtimestamp(time.time() - dur):%H:%M}).")
            flush_outbox()
        time.sleep(n["every"])


def http_checks_loop():
    checks = CFG["http_checks"]
    down = {}
    while True:
        for chk in checks:
            name, url = chk["name"], chk["url"]
            expect = chk.get("expect_status", [200, 301, 302, 401, 403])
            try:
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "notifyarr"})
                with urllib.request.urlopen(req, timeout=chk.get("timeout", 15)) as r:
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception as e:  # noqa: BLE001
                code = f"error: {e}"
            ok = code in expect
            if not ok and name not in down and internet_up():
                down[name] = time.time()
                alert(("http", name), "host", chk.get("severity", "warning"), f"{name} is not reachable",
                      f"{url}\nResult: {code}")
            elif ok and name in down:
                dur = time.time() - down.pop(name)
                alert(("http-up", name, time.time()), "recovered", "info", f"{name} is reachable again",
                      f"{url}\nWas down for about {fmt_dur(dur)}.")
        time.sleep(CFG["http_every"])


# =========================================================================== UPS
def ups_apcupsd(host, port):
    import struct
    with socket.create_connection((host, port), timeout=10) as sk:
        sk.sendall(struct.pack(">H", 6) + b"status")
        data, buf = {}, b""
        while True:
            while len(buf) < 2:
                chunk = sk.recv(4096)
                if not chunk:
                    return data
                buf += chunk
            n = struct.unpack(">H", buf[:2])[0]
            if n == 0:
                return data
            while len(buf) < 2 + n:
                chunk = sk.recv(4096)
                if not chunk:
                    return data
                buf += chunk
            rec, buf = buf[2:2 + n].decode(errors="replace"), buf[2 + n:]
            if ":" in rec:
                k, v = rec.split(":", 1)
                data[k.strip()] = v.strip()


def ups_nut(host, port, name):
    data = {}
    with socket.create_connection((host, port), timeout=10) as sk:
        sk.sendall(f"LIST VAR {name}\n".encode())
        buf = b""
        while b"END LIST VAR" not in buf and b"ERR" not in buf[:3]:
            chunk = sk.recv(4096)
            if not chunk:
                break
            buf += chunk
    for line in buf.decode(errors="replace").splitlines():
        m = re.match(r'VAR \S+ (\S+) "(.*)"', line)
        if m:
            data[m.group(1)] = m.group(2)
    return data


def num(s):
    m = re.search(r"-?\d+(\.\d+)?", s or "")
    return float(m.group()) if m else None


def read_ups():
    u = CFG["ups"]
    if u["kind"] == "nut":
        d = ups_nut(u["host"], u["port"], u["name"])
        flags = set((d.get("ups.status") or "").split())
        res = (d.get("ups.test.result") or "").lower()
        return {
            "model": d.get("ups.model") or d.get("device.model", "UPS"),
            "online": "OL" in flags, "onbatt": "OB" in flags, "lowbatt": "LB" in flags,
            "replace": "RB" in flags, "charge": num(d.get("battery.charge")),
            "runtime": (num(d.get("battery.runtime")) or 0) / 60 if d.get("battery.runtime") else None,
            "load": num(d.get("ups.load")), "battdate": d.get("battery.date") or d.get("battery.mfr.date"),
            "selftest_bad": any(w in res for w in ("fail", "bad", "error")), "selftest": res,
            "status": d.get("ups.status", "?"),
        }
    d = ups_apcupsd(u["host"], u["port"])
    st = (d.get("STATUS") or "").upper()
    test = (d.get("SELFTEST") or "").upper()
    return {
        "model": d.get("MODEL", "UPS"),
        "online": "ONLINE" in st, "onbatt": "ONBATT" in st, "lowbatt": "LOWBATT" in st,
        "replace": "REPLACEBATT" in st, "commlost": "COMMLOST" in st,
        "charge": num(d.get("BCHARGE")), "runtime": num(d.get("TIMELEFT")), "load": num(d.get("LOADPCT")),
        "battdate": d.get("BATTDATE"), "selftest_bad": test in ("NG", "BT"),
        "selftest": {"OK": "passed", "NG": "failed (overload)", "BT": "failed (battery)",
                     "NO": "none run", "IP": "in progress"}.get(test, test.lower()),
        "status": st,
    }


UPS_STATE = {}


def ups_loop():
    u = CFG["ups"]
    st = {"onbatt_since": None, "unreachable": False, "weekly": 0, "low_charge_since": None}
    while True:
        now = time.time()
        try:
            d = read_ups()
            UPS_STATE.clear()
            UPS_STATE.update(d)
            if st["unreachable"]:
                st["unreachable"] = False
                alert(("ups-ok", now), "recovered", "info", "UPS connection restored", d["model"])
        except Exception as e:  # noqa: BLE001
            if not st["unreachable"]:
                st["unreachable"] = True
                alert(("ups-unreach",), "host", "warning", "Can't read the UPS",
                      f"{u['kind']} at {u['host']}:{u['port']}: {e}\n"
                      "Check Settings > UPS Settings in Unraid (Network Information Server on).")
            time.sleep(u["every"])
            continue
        info = (f"Model: {d['model']}\nCharge: {d['charge']}%  Runtime: {d['runtime']} min  "
                f"Load: {d['load']}%\nStatus: {d['status']}")
        if d.get("commlost"):
            alert(("ups-comm",), "host", "warning", "UPS communication lost", info)
        if d["onbatt"] and st["onbatt_since"] is None:
            st["onbatt_since"] = now
            alert(("ups-ob", now), "host", u["on_battery"], "Power cut: server is on UPS battery", info)
        elif not d["onbatt"] and st["onbatt_since"] is not None:
            dur = now - st["onbatt_since"]
            st["onbatt_since"] = None
            alert(("ups-ol", now), "recovered", "warning", "Mains power is back",
                  f"Ran on battery for {fmt_dur(dur)}.\n{info}")
        if d["lowbatt"] or (d["onbatt"] and d["runtime"] is not None and d["runtime"] <= u["min_runtime"]):
            alert(("ups-lb",), "host", u["low_battery"], "UPS battery LOW: shutdown is close", info)
        # ---- battery health
        if d["replace"]:
            alert(("ups-rb",), "host", u["health"], "UPS says the battery needs replacing", info)
        if d["selftest_bad"]:
            alert(("ups-test", d["selftest"]), "host", u["health"], f"UPS self-test {d['selftest']}", info)
        if d["online"] and d["charge"] is not None and d["charge"] < u["min_charge"]:
            st["low_charge_since"] = st["low_charge_since"] or now
            if now - st["low_charge_since"] > 6 * 3600:
                alert(("ups-charge",), "host", u["health"], "UPS battery isn't charging fully",
                      f"Charge has stayed below {u['min_charge']:.0f}% for 6+ hours on mains power. "
                      f"The battery may be worn out.\n{info}")
        else:
            st["low_charge_since"] = None
        if now - st["weekly"] > 7 * 86400 and d.get("battdate"):
            st["weekly"] = now
            try:
                bd = datetime.strptime(re.sub(r"[/.]", "-", d["battdate"])[:10], "%Y-%m-%d")
                age = (datetime.now() - bd).days / 365.25
                if age >= u["max_age_years"]:
                    alert(("ups-age",), "host", u["health"], f"UPS battery is {age:.1f} years old",
                          f"Battery date: {d['battdate']}. Lead-acid UPS batteries usually last 3-5 years; "
                          f"run a self-test and plan a replacement.\n{info}")
            except ValueError:
                pass
        time.sleep(u["every"])


# =========================================================================== backups
def newest_mtime(path, depth=3):
    best = 0
    base = path.rstrip("/").count("/")
    for root, dirs, files in os.walk(path):
        if root.count("/") - base >= depth:
            dirs[:] = []
        for f in files:
            try:
                best = max(best, os.path.getmtime(os.path.join(root, f)))
            except OSError:
                pass
    return best


def backups_loop():
    b = CFG["backups"]
    while True:
        for chk in b["checks"]:
            name, path = chk["name"], chk["path"]
            max_h = float(chk.get("max_age_hours", 26))
            if not os.path.isdir(path):
                alert(("backup", name, "missing"), "backup", b["severity"], f"Backup '{name}': folder missing",
                      f"{path} doesn't exist or isn't mounted.")
                continue
            t = newest_mtime(path)
            age = (time.time() - t) / 3600 if t else None
            if age is None or age > max_h:
                when = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "never"
                alert(("backup", name, "stale"), "backup", chk.get("severity", b["severity"]),
                      f"Backup '{name}' is out of date",
                      f"Newest file in {path}: {when} ({'no files' if age is None else f'{age:.0f} h ago'}). "
                      f"Expected one within {max_h:.0f} h. Check the backup job's log.")
        time.sleep(b["every"])


# =========================================================================== hardware / firmware
VENDORS = [
    # (match in board/system vendor, support page, how BIOS updates are done)
    ("asus", "https://www.asus.com/support/", "ASUS EZ Flash, built into the BIOS (Tool menu), from a FAT32 USB stick. "
     "Many boards also support USB BIOS FlashBack (button on the rear I/O) with no CPU/RAM needed."),
    ("gigabyte", "https://www.gigabyte.com/Support", "Q-Flash, built into the BIOS (press End at boot or use the "
     "Q-Flash menu), from a FAT32 USB stick. Some boards have Q-Flash Plus (button on the rear I/O)."),
    ("micro-star", "https://www.msi.com/support", "M-Flash, built into the BIOS, from a FAT32 USB stick. "
     "Some boards have Flash BIOS Button on the rear I/O."),
    ("msi", "https://www.msi.com/support", "M-Flash, built into the BIOS, from a FAT32 USB stick."),
    ("asrock", "https://www.asrock.com/support/index.asp", "Instant Flash, built into the BIOS (Tool menu), "
     "from a FAT32 USB stick."),
    ("supermicro", "https://www.supermicro.com/en/support/resources/downloadcenter/swdownload",
     "From the IPMI/BMC web interface (Maintenance > BIOS Update), or the vendor's UEFI shell flash package."),
    ("dell", "https://www.dell.com/support", "Dell's BIOS update file run from the F12 one-time boot menu "
     "(BIOS Flash Update) using a FAT32 USB stick, or via iDRAC on servers."),
    ("hewlett", "https://support.hp.com", "HP's BIOS update from the F10 BIOS menu or a FAT32 USB stick "
     "(HP_TOOLS); on servers via iLO."),
    ("hp", "https://support.hp.com", "HP's BIOS update from the F10 BIOS menu or a FAT32 USB stick."),
    ("lenovo", "https://pcsupport.lenovo.com", "Lenovo's bootable BIOS update (ISO/USB) from the support page."),
    ("intel", "https://www.asus.com/support/", "Intel NUC support moved to ASUS. Use the F7 BIOS update "
     "from a FAT32 USB stick."),
    ("biostar", "https://www.biostar.com.tw/app/en/support/", "BIO-Flasher in the BIOS, from a FAT32 USB stick."),
]

FLASH_SAFETY = (
    "Before you update:\n"
    "1. Back up the Unraid USB flash drive (Main > Flash > Flash Backup).\n"
    "2. Stop the array and shut down VMs/containers.\n"
    "3. Make sure the server is on a UPS. Never power off during a flash.\n"
    "4. Download ONLY from the vendor page for your EXACT board model and revision.\n"
    "5. Read the release notes; some updates must be applied in order.\n"
    "6. After flashing, BIOS settings may reset to defaults: re-check boot order (USB first), "
    "VT-d/IOMMU, virtualisation, C-states, XMP and fan curves before starting the array."
)


def read_dmi():
    d = CFG["hw"]["dmi"]
    out = {}
    for k in ("bios_vendor", "bios_version", "bios_date", "board_vendor", "board_name", "board_version",
              "sys_vendor", "product_name"):
        try:
            with open(os.path.join(d, k)) as f:
                out[k] = f.read().strip()
        except OSError:
            out[k] = ""
    return out


def read_disk_firmware():
    out = {}
    sd = CFG["hw"]["smart_dir"]
    try:
        names = os.listdir(sd)
    except OSError:
        return out
    for n in names:
        try:
            with open(os.path.join(sd, n), errors="replace") as f:
                txt = f.read(20000)
        except OSError:
            continue
        model = re.search(r"(?m)^(?:Device Model|Model Number|Product):\s*(.+)$", txt)
        fw = re.search(r"(?m)^(?:Firmware Version|Revision):\s*(.+)$", txt)
        if model or fw:
            out[n] = ((model.group(1).strip() if model else "?"), (fw.group(1).strip() if fw else "?"))
    return out


def vendor_info(dmi):
    v = f"{dmi.get('board_vendor', '')} {dmi.get('sys_vendor', '')}".lower()
    for key, url, how in VENDORS:
        if key in v:
            return url, how
    return None, ("Use the update method in your motherboard manual, from the vendor's support page "
                  "for your exact model.")


def hardware_report():
    dmi = read_dmi()
    url, how = vendor_info(dmi)
    board = f"{dmi['board_vendor']} {dmi['board_name']} {dmi['board_version']}".strip()
    lines = [f"Board: {board or 'unknown'}",
             f"System: {dmi['sys_vendor']} {dmi['product_name']}".strip(),
             f"BIOS: {dmi['bios_vendor']} {dmi['bios_version']} ({dmi['bios_date']})"]
    disks = read_disk_firmware()
    if disks:
        lines.append("\nDisk firmware:")
        lines += [f"  {n}: {m}  fw {fw}" for n, (m, fw) in sorted(disks.items())]
    lines.append("\nHow to check for a BIOS update:")
    lines.append(f"  Support page: {url or 'your board vendor site'}  (search for: {dmi['board_name'] or 'your model'})")
    lines.append(f"  Update method: {how}")
    lines.append("  Disk firmware: use the drive maker's tool (e.g. Seagate SeaTools, WD Dashboard, "
                 "Samsung Magician) on a separate PC, and only if the release notes fix a problem you have.")
    lines.append("\n" + FLASH_SAFETY)
    return "\n".join(lines), dmi, disks


def check_cmos(boot_ts):
    """Kernel logs the RTC time it read at boot. A big gap to the real boot time = CMOS clock was lost."""
    path = CFG["syslog"]
    if not path:
        return
    try:
        with open(path, errors="replace") as f:
            txt = f.read(4_000_000)
    except OSError:
        return
    m = re.search(r"rtc_cmos .*setting system clock to (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", txt)
    if not m:
        return
    rtc = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").timestamp()
    if boot_ts and abs(rtc - boot_ts) > 6 * 3600:
        alert(("cmos",), "host", "warning", "Clock was wrong at boot: CMOS battery may be dying",
              f"At boot the hardware clock said {m.group(1)} UTC. A clock that resets usually means the "
              "motherboard coin cell (CR2032) is flat. BIOS settings may also have reset: check boot order, "
              "virtualisation and fan settings. Replacing the battery is cheap and quick (power off, unplug first).")


def ipmi_vbat():
    try:
        out = subprocess.run(["ipmitool", "sensor"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        f = [x.strip() for x in line.split("|")]
        if len(f) > 2 and re.search(r"(?i)vbat|battery|cmos", f[0]) and "volt" in f[2].lower():
            v = num(f[1])
            if v is not None:
                return f[0], v
    return None


HW_STATE = {}


def hardware_loop():
    h = CFG["hw"]
    prev = load_state().get("hw", {})
    up = host_uptime()
    if h["cmos_check"] and up is not None and up < 3600:
        check_cmos(time.time() - up)
    while True:
        report, dmi, disks = hardware_report()
        HW_STATE["report"] = report
        cur = {"bios": dmi.get("bios_version"), "bios_date": dmi.get("bios_date"),
               "disks": {k: v[1] for k, v in disks.items()}}
        if prev and prev.get("bios") and cur["bios"] != prev.get("bios"):
            alert(("bios-change", cur["bios"]), "host", "info", "BIOS version changed",
                  f"BIOS went from {prev.get('bios')} to {cur['bios']}. If you didn't update it, the board "
                  "may have fallen back to a backup BIOS.\n\n" + report)
        for dn, fw in cur["disks"].items():
            if prev.get("disks", {}).get(dn) not in (None, fw):
                alert(("disk-fw", dn, fw), "disk", "info", f"Disk {dn} firmware changed to {fw}", report)
        if not prev:
            alert(("hw-inventory",), "host", h["severity"], "Hardware inventory", report)
        try:
            bd = datetime.strptime(dmi.get("bios_date", ""), "%m/%d/%Y")
            age = (datetime.now() - bd).days / 365.25
            if age >= h["bios_age_years"]:
                alert(("bios-age",), "host", h["severity"], f"BIOS is {age:.1f} years old: check for an update",
                      "There's no automatic feed for motherboard BIOS releases, so check the vendor page below. "
                      "Only update if the release notes fix something you need or a security issue.\n\n" + report)
        except ValueError:
            pass
        if h["ipmi"]:
            r = ipmi_vbat()
            if r and r[1] < h["vbat_min"]:
                alert(("vbat",), "host", "warning", f"CMOS battery low: {r[1]:.2f} V",
                      f"IPMI sensor {r[0]} reads {r[1]:.2f} V (healthy is about 3.0 V). Replace the CR2032 coin cell.")
        save_state(hw=cur)
        prev = cur
        time.sleep(h["every"])


# =========================================================================== disk health (SMART)
LIFE_ATTRS = {"231": "SSD_Life_Left", "233": "Media_Wearout_Indicator", "177": "Wear_Leveling_Count",
              "202": "Percent_Lifetime_Remain", "169": "Remaining_Lifetime_Perc", "173": "Wear_Leveling"}
BAD_ATTRS = {"5": "Reallocated sectors", "187": "Reported uncorrectable", "197": "Pending sectors",
             "198": "Offline uncorrectable", "199": "UDMA CRC errors (often a cable)"}


def parse_smart(txt):
    """Return dict with life_left %, power_on_hours, bad counters, failed flag from smartctl text."""
    out = {"life": None, "hours": None, "bad": {}, "failed": False, "nvme_warn": None}
    if re.search(r"(?i)overall-health self-assessment test result:\s*FAILED|SMART Health Status:\s*(?!OK)\S+", txt):
        out["failed"] = True
    for line in txt.splitlines():
        f = line.split()
        if len(f) >= 10 and f[0].isdigit():
            aid, value, raw = f[0], f[3], f[9]
            if aid in LIFE_ATTRS and value.isdigit():
                out["life"] = float(value)
            elif aid in BAD_ATTRS and raw.isdigit():
                out["bad"][BAD_ATTRS[aid]] = int(raw)
            elif aid == "9":
                out["hours"] = num(raw)
    m = re.search(r"(?mi)^Percentage Used:\s*(\d+)%", txt)
    if m:
        out["life"] = max(0.0, 100 - float(m.group(1)))
    m = re.search(r"(?mi)^Power On Hours:\s*([\d,]+)", txt)
    if m:
        out["hours"] = float(m.group(1).replace(",", ""))
    m = re.search(r"(?mi)^Media and Data Integrity Errors:\s*([\d,]+)", txt)
    if m:
        out["bad"]["Media/data integrity errors"] = int(m.group(1).replace(",", ""))
    m = re.search(r"(?mi)^Critical Warning:\s*(0x[0-9a-f]+)", txt)
    if m and int(m.group(1), 16):
        out["nvme_warn"] = m.group(1)
    m = re.search(r"(?mi)^Available Spare:\s*(\d+)%", txt)
    if m and int(m.group(1)) < 10:
        out["nvme_warn"] = f"available spare {m.group(1)}%"
    return out


DISK_HEALTH = {}


def smart_loop():
    sm = CFG["smart"]
    prev_bad = load_state().get("smart_bad", {})
    while True:
        try:
            names = [n for n in os.listdir(sm["path"]) if not n.startswith(".")]
        except OSError as e:
            log.warning("disk health: %s", e)
            names = []
        for n in names:
            try:
                with open(os.path.join(sm["path"], n), errors="replace") as f:
                    txt = f.read(60000)
            except OSError:
                continue
            d = parse_smart(txt)
            model = re.search(r"(?m)^(?:Device Model|Model Number):\s*(.+)$", txt)
            label = f"{n} ({model.group(1).strip()})" if model else n
            DISK_HEALTH[n] = d
            if d["failed"]:
                alert(("smart-fail", n), "disk", "critical", f"Disk {label} FAILED its SMART health check",
                      "Replace this disk as soon as possible and make sure your backups are current.")
            if d["nvme_warn"]:
                alert(("nvme", n), "disk", "critical", f"NVMe {label} critical warning", f"Status: {d['nvme_warn']}")
            if d["life"] is not None:
                sev = "critical" if d["life"] <= sm["life_crit"] else "warning" if d["life"] <= sm["life_warn"] else None
                if sev:
                    alert(("life", n, sev), "disk", sev, f"Disk {label}: {d['life']:.0f}% life left",
                          f"Estimated remaining endurance: {d['life']:.0f}%. Plan a replacement.")
            if d["hours"] and d["hours"] >= sm["hours_warn"]:
                alert(("age", n), "disk", "info", f"Disk {label} has run {d['hours'] / 8766:.1f} years",
                      f"Power-on hours: {d['hours']:.0f}. Older disks fail more often; keep an eye on it.")
            pb = prev_bad.get(n, {})
            grew = {k: v for k, v in d["bad"].items() if v > pb.get(k, 0)}
            if grew:
                lines = "\n".join(f"{k}: {pb.get(k, 0)} -> {v}" for k, v in grew.items())
                sev = "warning" if list(grew) == ["UDMA CRC errors (often a cable)"] else "critical"
                alert(("smart-bad", n, json.dumps(grew)), "disk", sev, f"Disk {label}: SMART errors increasing", lines)
            prev_bad[n] = d["bad"]
        save_state(smart_bad=prev_bad)
        time.sleep(sm["every"])


# =========================================================================== leftovers / unusual growth
def dir_size(path, budget=20.0):
    """Total size of a folder, giving up after `budget` seconds (returns (bytes, complete))."""
    total, t0 = 0, time.time()
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
        if time.time() - t0 > budget:
            return total, False
    return total, True


def gb(n):
    return f"{n / 1e9:.1f} GB" if n >= 1e8 else f"{n / 1e6:.0f} MB"


def cleanup_scan():
    """Report-only scan. Returns list of (title, lines, total_bytes). Nothing is ever deleted."""
    cl = CFG["cleanup"]
    findings = []
    df = docker_get("/system/df", timeout=600)
    containers = df.get("Containers") or []
    used_images = {c.get("ImageID") for c in containers}
    # images
    imgs = [i for i in (df.get("Images") or []) if i.get("Id") not in used_images and i.get("Containers", 0) <= 0]
    if imgs:
        tot = sum(i.get("Size", 0) for i in imgs)
        if tot >= cl["min_mb"] * 1e6:
            lines = [f"{(i.get('RepoTags') or ['<none>'])[0]}  {gb(i.get('Size', 0))}" for i in
                     sorted(imgs, key=lambda i: -i.get("Size", 0))[:25]]
            findings.append(("Unused images", lines, tot,
                             "Unraid: Docker tab > Advanced view, or run  docker image prune -a  (removes ALL unused)."))
    # volumes
    vols = [v for v in (df.get("Volumes") or []) if (v.get("UsageData") or {}).get("RefCount", 1) == 0]
    if vols:
        tot = sum(max((v.get("UsageData") or {}).get("Size", 0), 0) for v in vols)
        lines = [f"{v.get('Name', '')[:40]}  {gb(max((v.get('UsageData') or {}).get('Size', 0), 0))}" for v in vols[:25]]
        findings.append(("Volumes not used by any container", lines, tot,
                         "Check each one first, then  docker volume rm <name>."))
    # stopped containers
    old = []
    for c in containers:
        if c.get("State") == "exited":
            name = c["Names"][0].lstrip("/")
            try:
                fin = docker_get(f"/containers/{c['Id']}/json")["State"].get("FinishedAt", "")[:19]
                age = (datetime.now() - datetime.fromisoformat(fin)).days
            except Exception:  # noqa: BLE001
                continue
            if age >= cl["stopped_days"]:
                old.append(f"{name}  stopped {age} days ago  ({gb(c.get('SizeRw', 0) or 0)})")
    if old:
        findings.append((f"Containers stopped for {cl['stopped_days']}+ days", old, 0,
                         "Remove them from the Docker tab if you no longer use them (keep the template if unsure)."))
    # big writable layers (data being written inside docker.img instead of appdata)
    big = [(c["Names"][0].lstrip("/"), c.get("SizeRw", 0) or 0) for c in containers
           if (c.get("SizeRw", 0) or 0) >= cl["writable_gb"] * 1e9]
    for name, size in big:
        alert(("bigsize", name), "disk", "warning", f"{name} is storing {gb(size)} inside docker.img",
              f"{name}'s writable layer is {gb(size)}. That usually means a path inside the app isn't mapped to "
              "appdata or a share, so data is filling docker.img. Check its path mappings.")
    # orphaned appdata folders + growth
    ad = cl["appdata"]
    if ad and os.path.isdir(ad):
        referenced = set()
        for c in containers:
            for m in c.get("Mounts") or []:
                src = m.get("Source", "")
                for pre in cl["appdata_host_prefixes"]:
                    if src.startswith(pre):
                        referenced.add(src[len(pre):].lstrip("/").split("/")[0].lower())
        sizes = {}
        orphans = []
        for n in sorted(os.listdir(ad)):
            full = os.path.join(ad, n)
            if not os.path.isdir(full):
                continue
            size, done = dir_size(full, cl["size_budget"])
            sizes[n] = size
            if n.lower() not in referenced and n.lower() not in {x.lower() for x in cl["appdata_ignore"]}:
                orphans.append((n, size, done))
        if orphans:
            tot = sum(s for _, s, _ in orphans)
            lines = [f"{n}  {gb(s)}{'' if d else '+'}" for n, s, d in sorted(orphans, key=lambda x: -x[1])[:25]]
            findings.append(("Appdata folders no container uses", lines, tot,
                             "These may be left over from removed apps. Back up before deleting, and check "
                             "the folder isn't used by a VM, script or plugin."))
        prev = load_state().get("appdata_sizes", {})
        for n, size in sizes.items():
            p = prev.get(n)
            if p and size - p >= cl["growth_gb_per_day"] * 1e9:
                alert(("growth", n), "disk", "warning", f"appdata/{n} grew {gb(size - p)} since the last check",
                      f"{gb(p)} -> {gb(size)}. Unusually fast growth (logs, cache, transcodes or a database "
                      "that isn't cleaning up).")
        save_state(appdata_sizes=sizes)
    return findings


def cleanup_loop():
    cl = CFG["cleanup"]
    time.sleep(300)
    while True:
        try:
            findings = cleanup_scan()
            CLEANUP_STATE["findings"] = findings
            CLEANUP_STATE["at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            if findings:
                total = sum(f[2] for f in findings)
                body = []
                for title, lines, size, how in findings:
                    body.append(f"{title}{f' ({gb(size)})' if size else ''}:\n  " + "\n  ".join(lines) + f"\n  → {how}")
                alert(("cleanup",), "disk", cl["severity"], f"Leftovers found: about {gb(total)} could be freed",
                      "Notifyarr never deletes anything. Review these yourself:\n\n" + "\n\n".join(body))
        except Exception as e:  # noqa: BLE001
            log.warning("cleanup scan failed: %s", e)
        time.sleep(cl["every"])


CLEANUP_STATE = {}


# =========================================================================== main
def main():
    logging.basicConfig(level=env("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    setup_config()
    channels = [n for n, ok in (("telegram", CFG["tg_token"] and CFG["tg_chat"]),
                                ("email", CFG["smtp_host"] and CFG["email_to"])) if ok]
    if not channels:
        log.warning("No notification channel configured; alerts will only be logged.")
    log.info("starting; channels=%s quiet_hours=%s", ",".join(channels) or "none",
             CFG["quiet"]["enabled"])

    running = []
    for _ in range(30):
        try:
            running = docker_get("/containers/json")
            break
        except Exception as e:  # noqa: BLE001
            log.warning("waiting for Docker API: %s", e)
            time.sleep(2)

    watched = []
    for c in running:
        name = c["Names"][0].lstrip("/") if c.get("Names") else c["Id"][:12]
        if c["Id"].startswith(SELF_ID) or not wanted(name, c.get("Labels")):
            continue
        watched.append(name)
        start_log_watch(c["Id"])
        if "(unhealthy)" in (c.get("Status") or ""):
            _unhealthy.add(name)
            alert(("health", name), "unhealthy", CFG["ev"]["unhealthy"], f"{name} is unhealthy",
                  f"Container: {name}\nImage: {c.get('Image')}\nWas already unhealthy at startup.")

    if CFG["reboot"]["enabled"]:
        check_reboot()

    def on_term(*_):
        save_state(clean_stop=True, heartbeat=time.time())
        os._exit(0)
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    extras = []
    for enabled, target, label in ((CFG["syslog"], watch_syslog, "host syslog"),
                                   (CFG["unraid_notify"], watch_unraid_notifications, "Unraid notifications"),
                                   (CFG["cs"]["enabled"], crowdsec_loop, "CrowdSec"),
                                   (CFG["disks"]["enabled"], disk_loop, "disk space"),
                                   (CFG["updates"]["enabled"], updates_loop, "image updates"),
                                   (CFG["certs"]["enabled"], certs_loop, "SSL certificates"),
                                   (CFG["tasks"]["enabled"], unraid_tasks_loop, "Unraid array/mover/parity"),
                                   (CFG["wg"]["enabled"], wireguard_loop, "WireGuard"),
                                   (CFG["res"]["enabled"], resources_loop, "CPU/RAM/disk per container"),
                                   (CFG["net"]["enabled"], internet_loop, "internet connection"),
                                   (CFG["ups"]["enabled"], ups_loop, "UPS"),
                                   (CFG["smart"]["enabled"], smart_loop, "disk health"),
                                   (CFG["backups"]["enabled"] and CFG["backups"]["checks"], backups_loop, "backups"),
                                   (CFG["hw"]["enabled"], hardware_loop, "hardware/firmware"),
                                   (CFG["cleanup"]["enabled"], cleanup_loop, "leftovers and growth"),
                                   (CFG["http_checks"], http_checks_loop, "web checks"),
                                   (True, state_heartbeat_loop, None),
                                   (CFG["heartbeat"]["enabled"], heartbeat_loop, "daily summary"),
                                   (CFG["tg_commands"] and CFG["tg_token"] and CFG["tg_chat"],
                                    telegram_bot_loop, "Telegram commands")):
        if enabled:
            threading.Thread(target=target, daemon=True).start()
            if label:
                extras.append(label)
    threading.Thread(target=digest_loop, daemon=True).start()

    try:
        import gui
        gui.start(sys.modules[__name__])
    except Exception as e:  # noqa: BLE001
        log.warning("GUI failed to start: %s", e)

    if CFG["startup_message"]:
        body = f"Watching {len(watched)} container(s): {', '.join(sorted(watched))}"
        if extras:
            body += f"\nAlso watching: {', '.join(extras)}"
        if CFG["quiet"]["enabled"]:
            q = CFG["quiet"]
            body += (f"\nQuiet hours: {q['start'] // 60:02d}:{q['start'] % 60:02d}-"
                     f"{q['end'] // 60:02d}:{q['end'] % 60:02d} (only {q['allow']} gets through)")
        threading.Thread(target=deliver, args=("👀 Notifyarr is running", body, "info"),
                         daemon=True).start()

    watch_events()


if __name__ == "__main__":
    main()
