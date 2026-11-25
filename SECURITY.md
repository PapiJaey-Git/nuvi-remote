# Security Policy

## End-to-End Encryption (E2EE)
NUVI Remote uses an opaque relay architecture (`nuvi-server`). The relay server **never** sees desktop frames, keyboard/mouse input, clipboard text, file transfers, or in-session chat:

- **Identity:** Ed25519 identity keypair per installation (`NUVI-XXX-XXX-XXX` derived deterministically from the public key).
- **Relay Registration Proof-of-Possession:** `nuvi-server` issues a random 32-byte `ServerChallenge` nonce on WebSocket connect; `nuvi-client` must sign `(device_id, nonce)` with its Ed25519 private key before registering, preventing unauthenticated Device ID eviction.
- **Key Exchange & Key Pinning:** Ephemeral X25519 ECDH signed with each peer's Ed25519 identity key. `nuvi-host` verifies `device_id_from_pubkey(peer_key) == target_device_id` and enforces Trust-On-First-Use (TOFU) public-key pinning per `device_id` in `HostConfig.pinned_keys`.
- **Session Cipher:** Directional `ChaCha20-Poly1305` AEAD with monotonic nonce counters and size-bounded message decoding (`16 MiB` limit).
- **Transport Recommendation:** Always deploy `nuvi-server` behind TLS (`wss://`) on untrusted networks (Caddy, Fly.io, Cloudflare Tunnel, or Tailscale).
- **Unattended Keys & Windows Service Hardening:**
  - Unattended keys are hashed at rest with Argon2id (5-failure exponential brute-force lockout) and encrypted locally with Windows DPAPI (`CurrentUser` in Portable mode, `CRYPTPROTECT_LOCAL_MACHINE` in Service mode).
  - `C:\ProgramData\NUVI Remote\client` is locked down with a protected `SYSTEM` + `Administrators`-only DACL.
  - Service pipe administrative mutations, unattended key viewing, and consent acceptance require an Administrator token (`ImpersonateNamedPipeClient` + `CheckTokenMembership`).
  - Incoming file transfers are blocked when View-Only (`allow_control = false`) or Paused, enforce size/concurrency caps, sanitize Windows reserved filenames, and auto-rename collisions rather than overwriting existing files.

## Auth Modes (`private` vs `open`)
- **`NUVI_AUTH_MODE=private` (recommended for teams/MSPs):** Requires `NUVI_TECH_KEY` on `nuvi-host` (auto-generated to `/data/tech.key` on first start if unset) and enables `/api/devices` & `/api/audit`.
- **`NUVI_AUTH_MODE=open` (personal/public relay):** Disables `NUVI_TECH_KEY` and returns `403` on `/api/devices` and `/api/audit` so strangers cannot enumerate online PCs. Security relies on E2EE plus client-side **Accept/Decline** or rotating **Unattended Key**.

## Reporting a Vulnerability
Please report security issues privately via GitHub Security Advisories or directly to the maintainers before opening a public issue.
