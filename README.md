# KeyAuth

Password-free player authentication for offline-mode Forge 1.20.1 servers.

Each client generates an Ed25519 key pair on first launch. During login the server sends a random
challenge; the client signs it. The first valid key seen for a name is bound to it, and from then on
only that key can log in as that name — from any network.

## Install

Put `keyauth-<version>.jar` in **both** the server's `mods/` and the client modpack. The mod is
required on both sides: clients without it are rejected by Forge's channel check.

Only dedicated servers enforce. Singleplayer and LAN worlds are unaffected.

## Admin

| Command (op level 3) | Effect |
|---|---|
| `/keyauth list` | Registered names, key fingerprints, registration time |
| `/keyauth reset <player>` | Forget a player's key; their next join registers a new one |

A player on a new device, or after deleting their game folder, gets *"registered to another device"* —
reset them and they're bound to the new key on their next join.

If the server whitelist is on, only whitelisted names can register a key. With it off, any unclaimed
name can be claimed by whoever joins first.

## Files

| Side | Path | Contents |
|---|---|---|
| Server | `config/keyauth/keys.json` | Name → public key bindings |
| Client | `config/keyauth/identity.json` | The player's private key — anyone with this file can log in as them |

If `keys.json` exists but can't be read, the server refuses to start rather than letting every name
be re-claimed.

## Limits

- Offline mode has no connection encryption; KeyAuth authenticates the login, not the session after it.
- A player who joins a malicious server could have their signature relayed to this one during that
  login. Signatures are single-use and expire after 60 s.

## Build

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 17) ./gradlew build   # → build/libs/keyauth-<version>.jar
```
