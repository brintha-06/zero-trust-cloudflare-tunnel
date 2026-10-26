# Zero-Trust Network Access with Cloudflare Tunnels

A cybersecurity project that exposes an internal web application **without opening any inbound firewall ports**, using Cloudflare Tunnel (`cloudflared`) and Cloudflare Access to enforce identity-based access.

## Why Zero Trust?
Traditional VPNs trust anyone inside the network. Zero Trust follows *"never trust, always verify"*: every request is authenticated and authorized, regardless of network location.

## Architecture
```
User ──HTTPS──> Cloudflare Edge (Access: SSO + MFA + policy)
                      │
                      │  outbound-only encrypted tunnel
                      ▼
               cloudflared (on server) ──> Flask app (127.0.0.1:5000)
```
- No public IP or open inbound ports on the server
- Cloudflare Access authenticates users (email OTP / Google SSO + MFA)
- The app re-validates the Cloudflare Access JWT (defence in depth)

## Project Files
| File | Purpose |
|------|---------|
| `zero_trust_tunnel.py` | Config generator, protected app, posture checker |
| `requirements.txt` | Python dependencies |
| `README.md` | This file |
| `Project_Report.pdf` | Full project report |

## Prerequisites
- A Cloudflare account and a domain managed by Cloudflare
- Python 3.9+
- `cloudflared` installed ([download](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/))

## Setup
```bash
git clone <your-repo-url> && cd <repo>
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 1. Create the tunnel
```bash
cloudflared tunnel login
cloudflared tunnel create zt-tunnel
cloudflared tunnel route dns zt-tunnel app.example.com
```

### 2. Generate config
```bash
python zero_trust_tunnel.py config --tunnel-id <TUNNEL_ID> --hostname app.example.com
```

### 3. Create an Access application
In **Cloudflare Zero Trust → Access → Applications**, add a *Self-hosted* app for `app.example.com`, and a policy that allows only specific emails / identity-provider groups with MFA. Copy the **AUD tag**.

### 4. Run the app and tunnel
```bash
export CF_TEAM_DOMAIN=myteam.cloudflareaccess.com
export CF_ACCESS_AUD=<AUD_TAG>
python zero_trust_tunnel.py serve          # terminal 1
cloudflared tunnel --config config.yml run zt-tunnel   # terminal 2
```
For local testing only: `DEV_MODE=1 python zero_trust_tunnel.py serve`

### 5. Verify security posture
```bash
python zero_trust_tunnel.py check --hostname app.example.com
```

## Security Controls
- Outbound-only tunnel (no inbound ports)
- App bound to `127.0.0.1`
- Identity + MFA via Cloudflare Access
- JWT signature, expiry and audience validation
- Catch-all ingress rule returns 404
- No secrets in code (environment variables)

## Author
Brintha D — CSE(Cybersecurity), Sona College of Technology (2026–2027)
