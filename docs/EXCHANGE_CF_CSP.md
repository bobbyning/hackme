# exchange.hackme.tech — framing CSP (hub iframe)

**Origin** is Caddy on `89.150.41.40` (`scripts/ops/caddy/exchange.Caddyfile`), not the
legacy nginx sketch in `scripts/ops/nginx/hackme-exchange-domain.tls.conf`.

Required HTTP response headers (browsers ignore `frame-ancestors` in `<meta>`):

- `Content-Security-Policy` with
  `frame-ancestors 'self' https://hackme.tech http://127.0.0.1:8080 http://localhost:8080`
  (full paper policy: fonts / Binance / CF insights — see Caddyfile)
- `Cross-Origin-Resource-Policy: cross-origin`
- **No** `X-Frame-Options: SAMEORIGIN` (use `-X-Frame-Options` in Caddy)

## Status (2026-09-30)

Origin Caddy fixed + paper SPA redeployed. Public edge
(`curl -sI https://exchange.hackme.tech/`) now passes CSP + CORP and does **not**
send `X-Frame-Options`. Hub `#exchange` iframe framing is **GO**.

`npm run smoke:live` (paper SPA) asserts HTTP CSP + no `XFO: SAMEORIGIN`.

## If edge regresses

1. On origin: `caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy`
2. Confirm origin-direct:
   ```bash
   curl -skI --resolve exchange.hackme.tech:443:89.150.41.40 https://exchange.hackme.tech/ \
     | grep -iE 'content-security|x-frame|cross-origin-resource'
   ```
3. If origin is good but CF edge still injects `X-Frame-Options: SAMEORIGIN`, use
   Cloudflare → Rules → Transform Rules → Modify Response Header for
   `exchange.hackme.tech`: remove `X-Frame-Options`, set CSP / CORP as above, purge cache.

Do **not** assume CF is the only source of XFO — the regression that blocked hub
embed was origin Caddy shipping `X-Frame-Options: SAMEORIGIN` without CSP.
