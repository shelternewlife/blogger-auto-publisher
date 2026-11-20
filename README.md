# Blogger Auto Publisher

A private, self-hosted MCP server that lets ChatGPT list multiple Blogger blogs and publish a complete HTML article immediately to the blog selected by the user.

## Architecture

- Cloudflare Worker: HTTPS MCP endpoint and OAuth authorization server.
- Cloudflare KV: short-lived OAuth sessions and the encrypted Google refresh token.
- Google OAuth 2.0: grants the Blogger API scope `https://www.googleapis.com/auth/blogger`.
- Blogger API v3: lists blogs, publishes posts with `isDraft=false`, and retrieves posts.
- GitHub Actions: manual-only validation and deployment. No automatic workflow runs on push.

The Cloudflare Workers Free plan is sufficient for a low-volume personal publisher within its published usage limits. See [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) and [KV limits](https://developers.cloudflare.com/kv/platform/limits/).

## Security model

- ChatGPT authenticates to the MCP server using OAuth 2.1 authorization code + PKCE.
- The MCP login password is only used to authorize your own ChatGPT connection.
- Google OAuth is a separate connection performed by the administrator at `/admin/google`.
- The Google refresh token is encrypted using AES-256-GCM before it is written to KV.
- Never commit OAuth secrets, encryption keys, passwords, or refresh tokens.
- The server validates the selected `blogId` against the connected Google account before publishing.
- Publishing is immediate and public. The `publish_post` tool must only be called when the user explicitly asks to publish.

## 1. Create a Cloudflare Worker and KV namespace

1. Create or sign in to a Cloudflare account: https://dash.cloudflare.com/
2. Open **Workers & Pages** and create a KV namespace named `BLOGGER_AUTO_PUBLISHER`.
3. Copy the namespace ID.
4. Replace `REPLACE_WITH_YOUR_CLOUDFLARE_KV_NAMESPACE_ID` in `wrangler.toml` with that ID.
5. Create a Cloudflare API token with **Account / Workers Scripts / Edit** and **Account / Workers KV Storage / Edit** permissions.
6. In GitHub repository Settings → Secrets and variables → Actions, add:
   - `CLOUDFLARE_API_TOKEN`
   - `CLOUDFLARE_ACCOUNT_ID`

## 2. Configure Google Blogger OAuth

1. Open https://console.cloud.google.com/ and create a Google Cloud project.
2. Enable **Blogger API v3**.
3. Configure the OAuth consent screen. Add your Google account as a test user if the app remains in testing.
4. Create an OAuth Client ID of type **Web application**.
5. After the first deployment, add this exact authorized redirect URI:
   `https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/oauth/google/callback`
6. Copy the Google OAuth Client ID and Client Secret.

Generate a 32-byte encryption key locally or in a trusted password manager. Example command (do not commit its output):

```bash
openssl rand -base64 32
```

In Cloudflare Dashboard → Worker → Settings → Variables and Secrets, add these as **encrypted secrets**:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_TOKEN_ENCRYPTION_KEY` (base64 encoding of exactly 32 random bytes)
- `MCP_LOGIN_PASSWORD` (use a long, unique password)

The Worker also needs the KV binding named `OAUTH_KV`. The binding is declared in `wrangler.toml`.

## 3. Deploy

The workflow is intentionally manual-only:

1. Open GitHub → Actions → **Validate and deploy Blogger Auto Publisher**.
2. Select **Run workflow** on `main`.
3. Wait for type-check, tests, and deployment to complete.
4. Your Worker URL will be shown in the deployment log, normally:
   `https://blogger-auto-publisher.YOUR-SUBDOMAIN.workers.dev`

You can also deploy from a trusted terminal with `npm install` and `npx wrangler deploy`; no local setup is required if you use GitHub Actions.

## 4. Connect Google Blogger

1. Open `https://YOUR-WORKER/admin/google`.
2. Enter the `MCP_LOGIN_PASSWORD` you configured.
3. Sign in to Google and grant Blogger access.
4. Return to `https://YOUR-WORKER/admin`; it should show **Google Blogger: Connected**.

The Google OAuth redirect URI must exactly match the Worker callback URL.

## 5. Connect ChatGPT

1. In ChatGPT, open Settings → Apps (or Connectors, depending on the client UI) → Advanced settings / Developer mode.
2. Add a custom MCP server with the HTTPS endpoint `https://YOUR-WORKER/mcp`.
3. Choose OAuth authentication. The server advertises protected-resource metadata, authorization-server metadata, and dynamic client registration.
4. Complete the authorization page using your `MCP_LOGIN_PASSWORD`.

ChatGPT's available custom MCP connection controls can vary by plan and workspace. If your account does not offer custom MCP server connections, the Worker can still be tested independently, but ChatGPT connection will require an account with that capability.

## 6. Use it

Ask ChatGPT: **"List my Blogger blogs."** It calls `list_blogs` and shows the available blog names and IDs.

Then select one and say: **"Publish this article on [blog name] now."** ChatGPT calls `publish_post` with the selected blog ID, title, HTML content, and optional labels. The server returns the live URL. It can also call `get_post` to verify a publication.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `list_blogs` | List blogs available to the connected Google account. |
| `publish_post` | Publish immediately with `isDraft=false`. |
| `get_post` | Retrieve a post and confirm its URL/status. |

## Local development

```bash
npm install
npm run dev
npm run typecheck
npm test
```

Create a local `.dev.vars` file for secrets and configure a local KV namespace binding before testing OAuth flows. Never add `.dev.vars` to Git.

## API references

- [Blogger API: list blogs](https://developers.google.com/blogger/docs/3.0/reference/blogs/listByUser)
- [Blogger API: insert post](https://developers.google.com/blogger/docs/3.0/reference/posts/insert)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Cloudflare Workers](https://developers.cloudflare.com/workers/)
