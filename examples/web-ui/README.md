# nullclaw Web UI Demo

This demo page is a minimal browser client for the `web` channel.

## Run the demo page

From repository root:

```bash
python3 -m http.server 8081
```

Open [http://127.0.0.1:8081/examples/web-ui/](http://127.0.0.1:8081/examples/web-ui/).

## Minimal config (local)

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "listen": "127.0.0.1",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token"
        }
      }
    }
  }
}
```

Use URL: `ws://127.0.0.1:32123/ws`.

## Remote host / reverse proxy

- Set `"listen": "0.0.0.0"` in nullclaw config.
- Expose via TLS proxy/CDN and connect from browser using `wss://...`.
- Add strict `"allowed_origins"` for your UI domain and extension origin.

Example:

```json
"allowed_origins": [
  "https://relay.nullclaw.io",
  "chrome-extension://your-extension-id"
]
```
