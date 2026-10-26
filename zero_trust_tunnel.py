#!/usr/bin/env python3
"""
Zero-Trust Network Access (ZTNA) with Cloudflare Tunnels
--------------------------------------------------------
One-file project containing three parts:

  1. config   -> generates the cloudflared tunnel config (config.yml)
  2. serve    -> internal Flask app that ONLY trusts requests carrying a valid
                 Cloudflare Access JWT (defence in depth: identity verified twice)
  3. check    -> verifies the zero-trust posture (no public exposure, tunnel
                 reachable, direct access blocked)

Usage:
  python zero_trust_tunnel.py config --tunnel-id <ID> --hostname app.example.com
  python zero_trust_tunnel.py serve
  python zero_trust_tunnel.py check --hostname app.example.com

Environment variables (for `serve`):
  CF_TEAM_DOMAIN  e.g. myteam.cloudflareaccess.com
  CF_ACCESS_AUD   Application Audience (AUD) tag from Cloudflare Access
  DEV_MODE=1      skip JWT validation (local testing ONLY)
"""
import argparse
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from functools import wraps

import requests
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ztna")

LOCAL_PORT = 5000


# ----------------------------------------------------------------------------
# 1. Tunnel configuration generator
# ----------------------------------------------------------------------------
def build_config(tunnel_id: str, hostname: str, port: int = LOCAL_PORT) -> dict:
    """Return a cloudflared ingress config. Traffic flows OUTBOUND only."""
    return {
        "tunnel": tunnel_id,
        "credentials-file": os.path.expanduser(f"~/.cloudflared/{tunnel_id}.json"),
        "ingress": [
            {"hostname": hostname, "service": f"http://localhost:{port}"},
            {"service": "http_status:404"},  # catch-all: deny everything else
        ],
    }


def cmd_config(args):
    cfg = build_config(args.tunnel_id, args.hostname, args.port)
    with open(args.output, "w") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False)
    log.info("Wrote %s", args.output)
    print(yaml.safe_dump(cfg, sort_keys=False))
    print("Next steps:\n"
          "  cloudflared tunnel login\n"
          "  cloudflared tunnel create zt-tunnel\n"
          f"  cloudflared tunnel route dns zt-tunnel {args.hostname}\n"
          f"  cloudflared tunnel --config {args.output} run zt-tunnel")


# ----------------------------------------------------------------------------
# 2. Protected internal application
# ----------------------------------------------------------------------------
def create_app():
    from flask import Flask, abort, jsonify, request
    import jwt  # PyJWT

    app = Flask(__name__)
    team = os.getenv("CF_TEAM_DOMAIN", "")
    aud = os.getenv("CF_ACCESS_AUD", "")
    dev_mode = os.getenv("DEV_MODE") == "1"
    jwks = jwt.PyJWKClient(f"https://{team}/cdn-cgi/access/certs") if team else None

    def require_access(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if dev_mode:
                request.user = "dev@local"
                return fn(*a, **kw)
            token = request.headers.get("Cf-Access-Jwt-Assertion")
            if not token or not jwks or not aud:
                log.warning("Denied: missing token/config from %s", request.remote_addr)
                abort(403)
            try:
                key = jwks.get_signing_key_from_jwt(token).key
                claims = jwt.decode(token, key, algorithms=["RS256"], audience=aud)
            except Exception as exc:  # invalid signature, expired, wrong aud...
                log.warning("Denied: invalid JWT (%s)", exc)
                abort(403)
            request.user = claims.get("email", "unknown")
            return fn(*a, **kw)
        return wrapper

    @app.get("/")
    @require_access
    def index():
        log.info("Access granted to %s", request.user)
        return jsonify(message="Welcome to the zero-trust protected app",
                       user=request.user,
                       time=datetime.now(timezone.utc).isoformat())

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app


def cmd_serve(args):
    # Bind to loopback only: the app is never reachable from the network directly.
    create_app().run(host="127.0.0.1", port=args.port)


# ----------------------------------------------------------------------------
# 3. Zero-trust posture checker
# ----------------------------------------------------------------------------
def port_open_externally(port: int) -> bool:
    """True if the port accepts connections on a non-loopback interface."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.error:
        return False
    if ip.startswith("127."):
        return False
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((ip, port)) == 0


def cmd_check(args):
    results = []

    exposed = port_open_externally(args.port)
    results.append(("App not exposed on public interface", not exposed))

    for p in (22, 80, 443):
        results.append((f"No inbound listener on port {p} (external IP)",
                        not port_open_externally(p)))

    try:
        r = requests.get(f"https://{args.hostname}/", timeout=10, allow_redirects=False)
        # Unauthenticated users must be redirected to login (302) or denied (401/403)
        results.append((f"Unauthenticated request blocked (HTTP {r.status_code})",
                        r.status_code in (301, 302, 401, 403)))
    except requests.RequestException as exc:
        results.append((f"Tunnel hostname reachable ({exc.__class__.__name__})", False))

    print("\nZero-Trust Posture Report\n" + "=" * 40)
    for name, ok in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    sys.exit(0 if all(ok for _, ok in results) else 1)


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("config", help="generate cloudflared config.yml")
    c.add_argument("--tunnel-id", required=True)
    c.add_argument("--hostname", required=True)
    c.add_argument("--port", type=int, default=LOCAL_PORT)
    c.add_argument("--output", default="config.yml")
    c.set_defaults(fn=cmd_config)

    s = sub.add_parser("serve", help="run protected internal app")
    s.add_argument("--port", type=int, default=LOCAL_PORT)
    s.set_defaults(fn=cmd_serve)

    k = sub.add_parser("check", help="verify zero-trust posture")
    k.add_argument("--hostname", required=True)
    k.add_argument("--port", type=int, default=LOCAL_PORT)
    k.set_defaults(fn=cmd_check)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
