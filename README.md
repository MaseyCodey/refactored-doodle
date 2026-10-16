# Mase Mail: permanent receive-only accounts

## What changed
- Username/password registration and login with salted PBKDF2 password hashes.
- 30-day revocable session tokens, stored only as SHA-256 hashes in D1; the browser keeps its session token only for the current tab session.
- Each account can create up to 20 persistent mailbox addresses, automatically combining random first and last names with a short random suffix (example `avery.bennett.3a1c9f@temp.mase-tech.online`).
- Emails are received by a Cloudflare Email Routing Worker and stored persistently in D1. Users only see their own inboxes.
- There are NO outbound email or compose/send API routes. Message HTML is never rendered as executable HTML.

## Deploy the backend
1. Back up the existing `mase-mail` Worker and D1 database **before replacing anything**. This package's tables are additive, but its Worker may replace endpoints from the old API.
2. On a PC with Node.js installed, open `worker/` in a terminal. Run `npm install` and `npx wrangler login`.
3. Run `npx wrangler d1 list`, find the **existing** `mase-mail` database ID, and paste it into `wrangler.toml`. Do not create a new database if you want to preserve the existing one.
4. Run `npm run db:setup`. This creates the new permanent-account tables without deleting other tables.
5. Run `npx wrangler secret put RATE_SALT` and enter a long random string (required for reliable privacy-preserving IP throttling; the fallback is only for local testing).
6. Run `npm run deploy`. The Worker URL should be `https://mase-mail.hellerud-mason.workers.dev`; if your account uses a different subdomain, update `API` in `site/index.html`.
7. In Cloudflare Email > Email Routing > Routes, ensure the **existing route for `temp.mase-tech.online`** invokes this Worker on incoming email. Preserve any existing routing/forwarding rules, including `mase@mase-tech.online`, rather than deleting or repointing them.
8. Host `site/index.html` and `site/CNAME` on your existing GitHub Pages repo (replace only its `index.html`). If the website origin is not `https://temp.mase-tech.online`, update `ALLOWED_ORIGIN` in wrangler.toml and redeploy.
9. Register, create an address, and test by emailing that address from an external account. Verify the message appears after refresh.

## Important cautions
This is a functional starter implementation, not a fully hardened commercial email provider. Cloudflare D1 quotas apply. There is no password reset, attachment storage, verification, abuse-reporting interface, automated spam filtering, or migration of previous temporary inbox messages. Protect against brute-force login attempts with a Cloudflare WAF rate-limit rule for `/auth/login`, `/auth/register`, and `/mailboxes`. Use Cloudflare Turnstile and verified recovery email before opening public registrations broadly. Sending is intentionally impossible through this app; existing separate forwarding routes are not modified by these files.

Note: `temp.mase-tech.online` must have DNS and Cloudflare Email Routing configured for receiving. GitHub Pages does not receive mail by itself. If you use that same domain for GitHub Pages, the existing DNS configuration must remain valid.
