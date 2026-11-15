# Self-hosting on a Node box

The default build targets Vercel. On your own machine, build the Node server instead.

## Build

```bash
NITRO_PRESET=node-server npm run build      # vite build, then migrations (needs DATABASE_URL)
```

Output: `.output/server/index.mjs`. Node 22 or newer.

The built server does **not** read `.env`. Give it the environment from the process manager
(`EnvironmentFile=` in systemd), and run plain-node scripts as `node --env-file=.env …`.

## Run (systemd)

```ini
[Service]
User=<service user>
WorkingDirectory=/path/to/app
EnvironmentFile=/path/to/app/.env
Environment=NODE_ENV=production HOST=127.0.0.1 PORT=8356
ExecStart=/path/to/node .output/server/index.mjs
Restart=always
```

Bind to loopback and publish through a reverse proxy or tunnel that terminates TLS.
`ECHO_VAULT_PUBLIC_URL` must be the public `https` origin.

## Do not put an identity gate in front of it

Telegram's webhook, agent OAuth, the credential cards and the browser injector all call the
public origin without a browser session. A gate such as Cloudflare Access breaks them. The
vault's own controls (OAuth, Telegram approval, the passkey console) are the gate.

## Check a build before pointing traffic at it

```bash
for p in /api/mcp /.well-known/oauth-authorization-server /console; do
  curl -s -o /dev/null -w "$p %{http_code}\n" http://127.0.0.1:8356$p
done
```

Expect `200`, `200`, and for `/console` either `503` (console off) or `303` to `/console/login`
(console on). A `500` on `/console` means the passkey library did not load: see the
`traceDeps` note in `vite.config.ts`.
