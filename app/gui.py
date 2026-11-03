"""Notifyarr web GUI: status, recent alerts, on/off switches, settings editor, trusted IPs.

Security model
  * Off unless GUI_PASSWORD is set.
  * Only answers clients whose IP is in the trusted list (LAN ranges by default), and refuses
    requests that came through a reverse proxy (X-Forwarded-For / Forwarded headers). It is
    meant for your LAN only: do not port-forward it or put it behind a public proxy.
  * Login with a session cookie (HttpOnly, SameSite=Strict), CSRF token on every form,
    lock-out after repeated failures, and a security alert for failed logins.
  * Secrets (.env) are never shown or written by the GUI; only "set / not set".
"""
import hmac
import html
import http.server
import os
import re
import secrets
import shutil
import sys
import threading
import time
import tomllib
import urllib.parse

W = None  # the watcher module, set by start()
SESSIONS = {}          # token -> (csrf, expires)
FAILS = {}             # ip -> [count, first_ts]
SESSION_TTL = 8 * 3600

TOGGLES = [
    ("Containers", [
        ("events", "enabled", "Crashes, OOM, unhealthy, restart loops"),
        ("logs", "enabled", "Error lines in container logs"),
        ("resources", "enabled", "Per-container CPU / RAM / disk limits"),
        ("updates", "enabled", "Image updates available"),
    ]),
    ("Unraid host", [
        ("host", "syslog", "Syslog: disk, kernel and login errors"),
        ("host", "unraid_notifications", "Forward Unraid notifications"),
        ("unraid_tasks", "enabled", "Array, parity / read checks, mover"),
        ("disk_health", "enabled", "Disk health and SSD life left (SMART)"),
        ("storage", "enabled", "Array, pools, docker.img and log space"),
        ("ups", "enabled", "UPS power and battery health"),
        ("hardware", "enabled", "BIOS / firmware report, CMOS battery"),
        ("cleanup", "enabled", "Leftover images, volumes, appdata and unusual growth"),
        ("reboot", "enabled", "Reboots and unclean shutdowns"),
        ("backups", "enabled", "Backups out of date"),
    ]),
    ("Network and security", [
        ("internet", "enabled", "Internet down / restored"),
        ("wireguard", "enabled", "WireGuard tunnels"),
        ("crowdsec", "enabled", "CrowdSec bans, faulty bans, geoblocks"),
        ("certs", "enabled", "SSL certificates expiring"),
    ]),
    ("Notifications", [
        ("quiet_hours", "enabled", "Quiet hours (only critical gets through)"),
        ("heartbeat", "enabled", "Daily all-OK summary"),
        ("telegram", "commands", "Telegram commands and Trust buttons"),
        ("privacy", "redact_secrets", "Mask passwords, tokens and API keys in alerts"),
        ("privacy", "include_log_lines", "Include log lines in alerts"),
    ]),
]

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--line:#e4e7ec;--acc:#e8692c;--ok:#1f9d55;
--warn:#c98a00;--crit:#d92d20;--info:#3b82f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mut:#98a2b3;
--line:#2a313d}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
background:var(--bg);color:var(--fg)}a{color:var(--acc)}
header{display:flex;gap:18px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);
background:var(--card);flex-wrap:wrap}header b{font-size:18px;margin-right:12px}
header a{text-decoration:none;color:var(--mut);font-weight:500}header a.on{color:var(--acc)}
main{max-width:1100px;margin:0 auto;padding:20px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 10px}.mut{color:var(--mut)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
pre{white-space:pre-wrap;word-break:break-word;margin:0;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);
vertical-align:top}th{font-weight:600;color:var(--mut);font-size:13px}
.sev{font-size:12px;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;white-space:nowrap}
.critical{background:var(--crit)}.warning{background:var(--warn)}.info{background:var(--info)}
.row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--line);gap:12px}
.row:last-child{border:0}
.sw{position:relative;width:44px;height:24px;flex:none}.sw input{opacity:0;width:0;height:0}
.sw span{position:absolute;inset:0;background:var(--line);border-radius:99px;cursor:pointer;transition:.15s}
.sw span:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+span{background:var(--acc)}.sw input:checked+span:before{transform:translateX(20px)}
textarea{width:100%;min-height:60vh;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);
color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px}
input[type=password],input[type=text]{padding:9px 10px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--fg);width:100%}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}
button.sec{background:transparent;color:var(--fg);border:1px solid var(--line)}
.msg{padding:10px 14px;border-radius:8px;margin-bottom:14px;background:var(--card);border-left:4px solid var(--ok)}
.msg.err{border-color:var(--crit)}.banner{border-left:4px solid var(--warn)}
.login{max-width:360px;margin:12vh auto}
"""


# --------------------------------------------------------------------------- toml text editing
def _section_span(text, section):
    m = re.search(rf"(?m)^\[{re.escape(section)}\]\s*(#.*)?$", text)
    if not m:
        return None
    nxt = re.search(r"(?m)^\[", text[m.end():])
    return m.end(), (m.end() + nxt.start()) if nxt else len(text)


def get_toggle(raw, section, key, default=False):
    v = raw.get(section, {}).get(key, default)
    return bool(v)


def set_toggle(text, section, key, value):
    val = "true" if value else "false"
    span = _section_span(text, section)
    if span is None:
        return text.rstrip() + f"\n\n[{section}]\n{key} = {val}\n"
    a, b = span
    body = text[a:b]
    rx = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*)(true|false)")
    if rx.search(body):
        body = rx.sub(lambda m: m.group(1) + val, body, count=1)
    else:
        body = f"\n{key} = {val}" + body
    return text[:a] + body + text[b:]


def rule_blocks(text):
    return [m for m in re.finditer(r"(?ms)^\[\[rules\]\]\s*$(.*?)(?=^\[|\Z)", text)]


def set_rule_enabled(text, idx, value):
    blocks = rule_blocks(text)
    if idx >= len(blocks):
        return text
    m = blocks[idx]
    body = m.group(1)
    val = "true" if value else "false"
    if re.search(r"(?m)^enabled\s*=", body):
        body = re.sub(r"(?m)^enabled\s*=\s*(true|false)", f"enabled = {val}", body, count=1)
    else:
        body = f"\nenabled = {val}" + body
    return text[:m.start(1)] + body + text[m.end(1):]


# --------------------------------------------------------------------------- helpers
def cfg_path():
    return W.env("CONFIG_FILE", "/config/config.toml")


def read_cfg_text():
    try:
        with open(cfg_path()) as f:
            return f.read()
    except OSError:
        return ""


def write_cfg_text(text):
    tomllib.loads(text)  # raises on invalid TOML
    p = cfg_path()
    if os.path.exists(p):
        shutil.copy2(p, p + ".bak")
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, p)


def restart_soon():
    def go():
        time.sleep(1.0)
        W.save_state(clean_stop=True)
        os.execv(sys.executable, [sys.executable, "-u"] + sys.argv)
    threading.Thread(target=go, daemon=True).start()


def esc(s):
    return html.escape(str(s if s is not None else ""))


def page(title, body, tab="", csrf="", flash=None):
    nav = ""
    if csrf:
        links = [("/", "Status"), ("/alerts", "Alerts"), ("/switches", "On / off"), ("/settings", "Settings"),
                 ("/ips", "Trusted IPs"), ("/hardware", "Hardware"), ("/about", "About")]
        nav = "".join(f'<a href="{u}" class="{"on" if tab == u else ""}">{t}</a>' for u, t in links)
        nav += (f'<form method="post" action="/logout" style="margin-left:auto"><input type="hidden" name="csrf" '
                f'value="{csrf}"><button class="sec">Log out</button></form>')
    fl = ""
    if flash:
        ok, msg = flash
        fl = f'<div class="msg {"" if ok else "err"}">{esc(msg)}</div>'
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>Notifyarr · {esc(title)}</title>"
            f"<style>{CSS}</style></head><body><header><b>🔔 Notifyarr</b>{nav}</header><main>{fl}{body}"
            f"</main></body></html>")


# --------------------------------------------------------------------------- handler
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Notifyarr"
    sys_version = ""

    def log_message(self, fmt, *args):
        W.log.debug("gui %s %s", self.client_address[0], fmt % args)

    # ---- access control
    def allowed(self):
        if any(h in self.headers for h in ("X-Forwarded-For", "Forwarded", "X-Real-IP")):
            self.plain(403, "Notifyarr's GUI must not be put behind a reverse proxy. Open it on your LAN.")
            return False
        ip = self.client_address[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if not W.TRUST.match(ip):
            W.alert(("gui-untrusted", ip), "security", "warning", f"GUI access attempt from {ip}",
                    f"Someone at {ip} (not in your trusted list) tried to open the Notifyarr GUI. "
                    "Check that the port is not forwarded to the internet.")
            self.plain(403, "Forbidden")
            return False
        return True

    def session(self):
        c = self.headers.get("Cookie", "")
        m = re.search(r"(?:^|;\s*)nsid=([\w-]+)", c)
        if not m:
            return None
        s = SESSIONS.get(m.group(1))
        if not s or s[1] < time.time():
            SESSIONS.pop(m.group(1), None)
            return None
        return m.group(1), s[0]

    def plain(self, code, text):
        b = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def html(self, body, code=200, cookie=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(b)

    def redirect(self, to, cookie=None):
        self.send_response(303)
        self.send_header("Location", to)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def form(self):
        n = min(int(self.headers.get("Content-Length", 0) or 0), 2_000_000)
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}

    # ---- routes
    def do_GET(self):
        if not self.allowed():
            return
        path = urllib.parse.urlparse(self.path).path
        s = self.session()
        if not s:
            return self.html(self.login_page())
        tok, csrf = s
        flash = None
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "ok" in q:
            flash = (True, q["ok"][0])
        if "err" in q:
            flash = (False, q["err"][0])
        routes = {"/": self.p_status, "/alerts": self.p_alerts, "/switches": self.p_switches,
                  "/settings": self.p_settings, "/ips": self.p_ips, "/hardware": self.p_hardware,
                  "/about": self.p_about}
        fn = routes.get(path)
        if not fn:
            return self.plain(404, "Not found")
        title, body = fn(csrf)
        self.html(page(title, body, path, csrf, flash))

    def do_POST(self):
        if not self.allowed():
            return
        path = urllib.parse.urlparse(self.path).path
        f = self.form()
        if path == "/login":
            return self.do_login(f)
        s = self.session()
        if not s or not hmac.compare_digest(f.get("csrf", ""), s[1]):
            return self.redirect("/")
        tok = s[0]
        try:
            if path == "/logout":
                SESSIONS.pop(tok, None)
                return self.redirect("/", cookie="nsid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")
            if path == "/switches":
                text = read_cfg_text()
                for group, items in TOGGLES:
                    for sec, key, _ in items:
                        text = set_toggle(text, sec, key, f.get(f"{sec}.{key}") == "on")
                for i, _ in enumerate(rule_blocks(text)):
                    text = set_rule_enabled(text, i, f.get(f"rule.{i}") == "on")
                write_cfg_text(text)
                restart_soon()
                return self.redirect("/switches?ok=Saved.+Notifyarr+is+restarting+to+apply+it.")
            if path == "/settings":
                try:
                    write_cfg_text(f.get("config", "").replace("\r\n", "\n"))
                except tomllib.TOMLDecodeError as e:
                    return self.redirect("/settings?err=" + urllib.parse.quote(f"Not saved, the file has an error: {e}"))
                restart_soon()
                return self.redirect("/settings?ok=Saved.+Notifyarr+is+restarting+to+apply+it.")
            if path == "/ips/add":
                n = W.TRUST.add(f.get("ip", ""), f.get("note", "") or "via GUI")
                return self.redirect("/ips?" + (f"ok=Trusted+{n}" if n else "err=Not+a+valid+IP+or+range"))
            if path == "/ips/remove":
                W.TRUST.remove(f.get("ip", ""))
                return self.redirect("/ips?ok=Removed")
            if path == "/test":
                threading.Thread(target=W.deliver, args=(
                    "🧪 Test alert", "If you can read this, Notifyarr can reach you.", "warning"), daemon=True).start()
                return self.redirect("/?ok=Test+alert+sent+to+every+configured+channel.")
        except Exception as e:  # noqa: BLE001
            W.log.exception("gui action failed")
            return self.redirect("/?err=" + urllib.parse.quote(str(e)[:200]))
        self.plain(404, "Not found")

    def do_login(self, f):
        ip = self.client_address[0]
        cnt, first = FAILS.get(ip, [0, time.time()])
        if cnt >= 5 and time.time() - first < 900:
            return self.html(self.login_page("Too many attempts. Try again in 15 minutes."), 429)
        if hmac.compare_digest(f.get("password", "").encode(), W.env("GUI_PASSWORD").encode()):
            FAILS.pop(ip, None)
            tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            SESSIONS[tok] = (csrf, time.time() + SESSION_TTL)
            return self.redirect("/", cookie=f"nsid={tok}; Max-Age={SESSION_TTL}; Path=/; HttpOnly; SameSite=Strict")
        if time.time() - first > 900:
            cnt, first = 0, time.time()
        FAILS[ip] = [cnt + 1, first]
        W.alert(("gui-login", ip), "security", "warning", f"Failed Notifyarr GUI login from {ip}",
                f"Wrong password entered for the Notifyarr GUI from {ip} ({cnt + 1} attempt(s)).")
        return self.html(self.login_page("Wrong password."), 401)

    # ---- pages
    def login_page(self, err=""):
        e = f'<div class="msg err">{esc(err)}</div>' if err else ""
        return page("Log in", f'<div class="card login"><h2>Log in</h2>{e}<form method="post" action="/login">'
                    f'<p><input type="password" name="password" placeholder="Password" autofocus required></p>'
                    f'<button>Log in</button></form></div>')

    def p_status(self, csrf):
        text, ok = W.status_text()
        ch = []
        if W.CFG["tg_token"] and W.CFG["tg_chat"]:
            ch.append("Telegram")
        if W.CFG["smtp_host"] and W.CFG["email_to"]:
            ch.append("Email")
        ups = W.UPS_STATE
        ups_html = (f"<pre>{esc(ups.get('model'))}\nStatus: {esc(ups.get('status'))}\nCharge: {esc(ups.get('charge'))}%"
                    f"  Runtime: {esc(ups.get('runtime'))} min  Load: {esc(ups.get('load'))}%\n"
                    f"Self-test: {esc(ups.get('selftest'))}  Battery date: {esc(ups.get('battdate'))}</pre>"
                    if ups else '<p class="mut">UPS check is off or not connected.</p>')
        def disk_row(n, d):
            life = "" if d["life"] is None else f"{d['life']:.0f}%"
            age = f"{d['hours'] / 8766:.1f} y" if d["hours"] else ""
            errs = ", ".join(f"{k}: {v}" for k, v in d["bad"].items() if v)
            return (f"<tr><td>{esc(n)}</td><td>{life}</td><td>{age}</td>"
                    f"<td>{'FAILED' if d['failed'] else 'OK'}</td><td>{esc(errs)}</td></tr>")
        disks = "".join(disk_row(n, d) for n, d in sorted(W.DISK_HEALTH.items()))
        disks_html = (f"<table><tr><th>Disk</th><th>Life left</th><th>Age</th><th>SMART</th><th>Errors</th></tr>{disks}</table>"
                      if disks else '<p class="mut">Disk health check is off or has not run yet.</p>')
        recent = "".join(f"<tr><td class=mut>{esc(a['t'][11:16])}</td><td><span class='sev {a['severity']}'>"
                         f"{a['severity']}</span></td><td>{esc(a['subject'])}</td></tr>"
                         for a in list(W.HISTORY)[-8:][::-1])
        cs = W.CLEANUP_STATE
        if cs.get("findings"):
            parts = []
            for title, lines, size, how in cs["findings"]:
                parts.append(f"<h3 style='font-size:14px;margin:12px 0 4px'>{esc(title)}"
                             f"{' · ' + W.gb(size) if size else ''}</h3><pre>{esc(chr(10).join(lines))}</pre>"
                             f"<p class=mut>{esc(how)}</p>")
            leftovers = (f'<div class="card"><h2>Leftovers (scanned {esc(cs.get("at"))})</h2>'
                         f'<p class="mut">Report only. Notifyarr never deletes anything.</p>{"".join(parts)}</div>')
        else:
            leftovers = ""
        body = (f'<div class="msg banner">Keep this page on your LAN. Never port-forward it or publish it through a '
                f'reverse proxy.</div>'
                f'<div class="grid"><div class="card"><h2>{"✅ All OK" if ok else "📋 Needs attention"}</h2>'
                f'<pre>{esc(text)}</pre></div>'
                f'<div class="card"><h2>Notifications</h2><p>Channels: <b>{esc(", ".join(ch) or "none set")}</b></p>'
                f'<p class="mut">Quiet hours are {"on now" if W.in_quiet_hours() else "off now"}.</p>'
                f'<form method="post" action="/test"><input type="hidden" name="csrf" value="{csrf}">'
                f'<button>Send a test alert</button></form></div>'
                f'<div class="card"><h2>UPS</h2>{ups_html}</div></div>'
                f'<div class="card"><h2>Disks</h2>{disks_html}</div>'
                f'{leftovers}'
                f'<div class="card"><h2>Latest alerts</h2><table>{recent or "<tr><td class=mut>None yet.</td></tr>"}</table></div>')
        return "Status", body

    def p_alerts(self, csrf):
        rows = "".join(f"<tr><td class=mut>{esc(a['t'].replace('T', ' '))}</td><td><span class='sev {a['severity']}'>"
                       f"{a['severity']}</span></td><td><b>{esc(a['subject'])}</b><pre class=mut>{esc(a['body'])}</pre></td></tr>"
                       for a in list(W.HISTORY)[::-1])
        return "Alerts", (f'<div class="card"><h2>Recent alerts</h2><p class="mut">Last 500 since Notifyarr started. '
                          f'Passwords, tokens and keys are masked before they are stored or sent.</p>'
                          f'<table>{rows or "<tr><td class=mut>None yet.</td></tr>"}</table></div>')

    def p_switches(self, csrf):
        raw = tomllib.loads(read_cfg_text() or "")
        out = [f'<form method="post" action="/switches"><input type="hidden" name="csrf" value="{csrf}">']
        out.append('<div class="grid">')
        for group, items in TOGGLES:
            out.append(f'<div class="card"><h2>{esc(group)}</h2>')
            for sec, key, label in items:
                default = key in ("syslog", "unraid_notifications", "commands", "redact_secrets", "include_log_lines") \
                    or sec in ("events", "logs", "reboot", "internet", "heartbeat")
                on = get_toggle(raw, sec, key, default)
                out.append(f'<label class="row"><span>{esc(label)}</span><span class="sw"><input type="checkbox" '
                           f'name="{sec}.{key}" {"checked" if on else ""}><span></span></span></label>')
            out.append("</div>")
        out.append('<div class="card"><h2>Log rules</h2>')
        for i, r in enumerate(raw.get("rules", [])):
            on = r.get("enabled", True)
            out.append(f'<label class="row"><span>{esc(r.get("name"))} <span class="mut">· {esc(r.get("severity", "warning"))}'
                       f'</span></span><span class="sw"><input type="checkbox" name="rule.{i}" '
                       f'{"checked" if on else ""}><span></span></span></label>')
        out.append('</div></div><button>Save and apply</button></form>')
        return "On / off", "".join(out)

    def p_settings(self, csrf):
        env_rows = "".join(
            f"<tr><td>{k}</td><td>{'set' if W.env(k) else '<span class=mut>not set</span>'}</td></tr>"
            for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD",
                      "EMAIL_TO", "CROWDSEC_BOUNCER_KEY", "GUI_PASSWORD"))
        return "Settings", (
            f'<div class="card"><h2>config.toml</h2><p class="mut">Thresholds, quiet hours, ignore rules, excluded '
            f'containers and every other option live here. It is checked before saving, the previous version is '
            f'kept as config.toml.bak, and Notifyarr restarts to apply it.</p>'
            f'<form method="post" action="/settings"><input type="hidden" name="csrf" value="{csrf}">'
            f'<textarea name="config" spellcheck="false">{esc(read_cfg_text())}</textarea>'
            f'<p><button>Save and apply</button></p></form></div>'
            f'<div class="card"><h2>Secrets</h2><p class="mut">Tokens and passwords are kept in the container\'s '
            f'environment (.env or the Unraid template), never in config.toml, and the GUI never shows them.</p>'
            f'<table>{env_rows}</table></div>')

    def p_ips(self, csrf):
        st, dyn = W.TRUST.listing()
        rows = "".join(f'<tr><td>{esc(n)}</td><td><form method="post" action="/ips/remove"><input type="hidden" '
                       f'name="csrf" value="{csrf}"><input type="hidden" name="ip" value="{esc(n)}">'
                       f'<button class="sec">Remove</button></form></td></tr>' for n in dyn)
        return "Trusted IPs", (
            f'<div class="card"><h2>Add a trusted IP or range</h2><form method="post" action="/ips/add" class="grid">'
            f'<input type="hidden" name="csrf" value="{csrf}"><input type="text" name="ip" placeholder="203.0.113.45 or 198.51.100.0/24" required>'
            f'<input type="text" name="note" placeholder="Note (optional), e.g. work"><button>Add</button></form></div>'
            f'<div class="grid"><div class="card"><h2>Added here or from Telegram</h2><table>{rows or "<tr><td class=mut>None.</td></tr>"}</table></div>'
            f'<div class="card"><h2>From config.toml</h2><pre>{esc(chr(10).join(st))}</pre></div></div>')

    def p_hardware(self, csrf):
        report = W.HW_STATE.get("report")
        if not report:
            try:
                report = W.hardware_report()[0]
            except Exception as e:  # noqa: BLE001
                report = f"Not available: {e}"
        return "Hardware", f'<div class="card"><h2>Hardware and firmware</h2><pre>{esc(report)}</pre></div>'

    def p_about(self, csrf):
        return "About", ABOUT_HTML


ABOUT_HTML = """
<div class="card"><h2>About the dev</h2>
<p>I'm an ISO 27001 Lead Auditor, so inspecting logs, finding where processes fail and spotting problems
early is what I do every day. I'm not a professional software developer.</p>
<p>I have combined-type ADHD, dyslexia and dyscalculia. I can read code and follow its logic and security well,
but writing it out myself isn't possible. So I design what Notifyarr does and how it works, and use AI as an
assistive tool to write the code from that design. I test changes against my own Unraid server before release.</p></div>
<div class="card"><h2>Contact</h2>
<p>Bugs, ideas and pull requests: <a href="https://github.com/p1zzm1ssile/Notifyarr/issues" rel="noreferrer">GitHub issues</a>.</p>
<p>For anything that doesn't belong on a public page, email
<a href="mailto:p1zzm1ssilerepo@gmail.com">p1zzm1ssilerepo@gmail.com</a>.</p>
<p class="mut">MIT licence. Not affiliated with Lime Technology (Unraid), Telegram or CrowdSec.</p></div>
"""


def start(watcher_module):
    global W
    W = watcher_module
    if not W.env("GUI_PASSWORD"):
        W.log.info("GUI disabled (set GUI_PASSWORD to enable it)")
        return
    if len(W.env("GUI_PASSWORD")) < 10:
        W.log.warning("GUI_PASSWORD is shorter than 10 characters; GUI disabled until you choose a longer one")
        return
    port = int(W.env("GUI_PORT", "8484"))
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    W.log.info("GUI listening on port %d (LAN only)", port)
