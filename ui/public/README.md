# ZECret public website

This is the public, fixture-only ZECret service website. It uses a TypeScript Cloudflare Worker with Workers Static Assets. The bundled native dashboard in `ui/local/` remains a separate application.

## Build and preview

Use the repository's managed Linux container for this checkout. From `ui/public/` inside the container:

```sh
pnpm install --frozen-lockfile
pnpm run build
pnpm run check
pnpm exec wrangler dev --ip 127.0.0.1 --port 8787 --local
```

With the development server running, open `http://127.0.0.1:8787/`. Run `pnpm run smoke` in the same container to check the public API and security headers.

The site reads fixed fixture scenarios through same-origin `GET /api/scenarios/{name}`. `GET /api/status` is a dated repository snapshot of the approved Phala-trusting testnet profile; it is not a live health or verification service. `GET /api/capabilities` lists informational method names. The Worker has no upstream fetch, database, wallet connection, ticket store, issuer key, or private RPC route.

## Publish on Workers Free

1. Create a Cloudflare account on the **Workers Free** plan and select its provided `workers.dev` subdomain in the [Workers dashboard](https://dash.cloudflare.com/). No custom domain or paid service is required.
2. In a private terminal, use `pnpm exec wrangler login --device --browser=false` and complete the approval in your browser. This [device flow](https://developers.cloudflare.com/workers/wrangler/commands/general/#use-wrangler-login-without-a-local-callback-server) works from a container without forwarding an OAuth callback port. Check the selected identity and account with `pnpm exec wrangler whoami`. Do not share login codes or API tokens in chat or a recorded terminal.
3. Review `worker.ts` for current release, payment, and chain status before publishing. Its status is deliberately dated and must match the reviewed release record; it does not assert current service health. Build and check again.
4. Deploy from `ui/public/` with the chosen Cloudflare account ID:

   ```sh
   CLOUDFLARE_ACCOUNT_ID=<selected-account-id> pnpm exec wrangler deploy
   ```

5. Open the `zecret-service.<your-account-subdomain>.workers.dev` URL reported by Wrangler. Check `/`, `/privacy`, `/api/status`, and the fixture demo on that URL. Keep the Workers plan on Free.

The `wrangler.jsonc` file enables only the provided `workers.dev` route and Static Assets. There is no D1, Durable Object, KV, paid binding, custom domain, analytics script, or application request logger. Cloudflare can still observe ordinary website traffic and visitor metadata; the site's privacy page explains this boundary.

Cloudflare currently documents [free static-asset requests](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/), [Workers Free request and CPU allowances](https://developers.cloudflare.com/workers/platform/pricing/), and the [provided `workers.dev` URL](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/). The free allowance can be exhausted; this site does not promise uninterrupted availability.
