# NUVI Remote (Open Source)

Pure-Rust, end-to-end encrypted remote desktop & remote support suite (`nuvi-server`, `nuvi-client`, `nuvi-host`).

## Highlights
- **End-to-End Encrypted Relay:** X25519 + Ed25519 signed handshake + directional `ChaCha20-Poly1305` for video, input, clipboard, file transfer, and in-session chat.
- **Client-Driven Attended / Unattended Auto-Detection:** The client decides whether a connection prompts **Accept / Decline** or challenges for its rotating **Unattended Key** (`NUVI-XXXX-XXXX-XXXX`) with Argon2id + DPAPI storage.
- **Windows Unattended Service Mode:** 1-click **Install for Unattended** (`NuviRemoteService`) for UAC prompts, Windows Lock Screen (`Ctrl+Alt+Del` via `SendSAS`), and remote Reboot with auto-reconnect.
- **DXGI Desktop Duplication + GDI Fallback:** Fast dirty-tile JPEG streaming, live cursor shape sync, multi-monitor switching, screen annotations/laser pointer, and multi-session tabs.
- **Zero-Domain & Cloud Ready:** Works over `wss://` (domain, Fly.io, Railway, Coolify, Cloudflare Tunnel) or raw `ws://` (VPS IP, Tailscale, LAN).

## 1. Self-Host the Relay Server (`nuvi-server`)
```bash
cd docker
cp .env.example .env
docker compose up -d --build
```
Set `NUVI_AUTH_MODE` in `docker/.env`:
- **`NUVI_AUTH_MODE=private`** *(default)*: Requires `NUVI_TECH_KEY` on `nuvi-host.exe` and enables `/api/devices` & `/api/audit`. Leave `NUVI_TECH_KEY=` blank on first boot to auto-generate a 48-char key (saved to `/data/tech.key` and printed in `docker logs nuvi-server`).
- **`NUVI_AUTH_MODE=open`**: No Tech Key required; `/api/devices` and `/api/audit` return `403`. Connections are gated strictly by E2EE + the client's **Accept/Decline** or rotating **Unattended Key**.

## 2. Configure `nuvi-host.exe` and `nuvi-client.exe`
1. Open **`nuvi-host.exe` -> Settings -> Server Address** and enter your server (domain like `remote.yourdomain.com`, VPS/Tailscale/LAN IP like `192.168.1.50`, or full `wss://...`/`ws://...`), then click **Save & Test**.
   - In `private` mode, paste your `NUVI_TECH_KEY` once.
   - In `open` mode, `nuvi-host` detects `"auth_mode": "open"` automatically and skips the Tech Key.
2. Click **Copy Client Setup** to copy a shareable `nuvi://...` code (never contains any Tech Key).
3. On the client PC, open **`nuvi-client.exe` -> Server** tab, paste the `nuvi://...` code (or server address), and click **Save & Reconnect** — **or** drop a 1-line `nuvi-server.txt` file next to `nuvi-client.exe`.

### Custom Default URL at Compile Time
To bake your own relay URL into `nuvi-client.exe` and `nuvi-host.exe`:
```powershell
$env:NUVI_DEFAULT_SERVER_URL = "wss://remote.yourdomain.com/ws"
cargo build --release -p nuvi-client -p nuvi-host
```

## 3. Build & Test Locally
```powershell
cargo test --workspace
cargo build --release -p nuvi-client -p nuvi-host
```

## License
Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE).
