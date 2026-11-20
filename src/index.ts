export interface Env {
  OAUTH_KV: KVNamespace;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_TOKEN_ENCRYPTION_KEY: string;
  MCP_LOGIN_PASSWORD: string;
  APP_NAME?: string;
}

type Json = Record<string, unknown>;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const GOOGLE_SCOPE = "https://www.googleapis.com/auth/blogger";
const MCP_SCOPE = "mcp:publish";
const ACCESS_TTL = 3600;
const REFRESH_TTL = 60 * 60 * 24 * 30;

function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
function html(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
function randomToken(bytes = 32): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}
function toBase64(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}
async function sha256(value: string): Promise<string> {
  return toBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function constantTimeEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}
function formPage(title: string, action: string, hidden: Record<string, string> = {}, note = ""): string {
  const fields = Object.entries(hidden).map(([k, v]) =>
    `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join("");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6fa;color:#172033;font:16px system-ui}
  main{width:min(440px,calc(100% - 32px));background:white;padding:32px;border-radius:18px;box-shadow:0 12px 40px #17203318}
  h1{font-size:24px;margin:0 0 8px}p{color:#596579;line-height:1.5}label{display:block;font-weight:600;margin:18px 0 8px}
  input{width:100%;padding:13px;border:1px solid #cbd3df;border-radius:9px;font:inherit}button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:9px;background:#1769e0;color:white;font-weight:700;font:inherit;cursor:pointer}
  small{display:block;color:#68758a;margin-top:16px}</style><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(note)}</p>
  <form method="post" action="${escapeHtml(action)}">${fields}<label>Administrator password</label><input name="password" type="password" required autocomplete="current-password"><button type="submit">Continue</button></form>
  <small>Your password is checked by this Worker and is never sent to Google.</small></main></html>`;
}
function cors(headers: Headers): Headers {
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  headers.set("access-control-allow-headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version");
  headers.set("access-control-expose-headers", "WWW-Authenticate, MCP-Session-Id");
  headers.set("access-control-max-age", "86400");
  return headers;
}
function withCors(response: Response): Response {
  const headers = cors(new Headers(response.headers));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
function originOf(request: Request): string {
  return new URL(request.url).origin;
}
function unauthorized(origin: string): Response {
  return json({ error: "unauthorized", error_description: "Connect this MCP server using OAuth." }, 401, {
    "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="${MCP_SCOPE}"`,
  });
}
async function requireAdmin(request: Request, env: Env): Promise<boolean> {
  const form = await request.formData();
  const supplied = String(form.get("password") ?? "");
  return Boolean(env.MCP_LOGIN_PASSWORD) && constantTimeEqual(supplied, env.MCP_LOGIN_PASSWORD);
}
async function encryptSecret(env: Env, plaintext: string): Promise<string> {
  const raw = fromBase64(env.GOOGLE_TOKEN_ENCRYPTION_KEY);
  if (raw.length !== 32) throw new Error("GOOGLE_TOKEN_ENCRYPTION_KEY must be base64 for exactly 32 random bytes.");
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(raw), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(encoder.encode(plaintext)));
  return JSON.stringify({ iv: toBase64(iv), data: toBase64(new Uint8Array(encrypted)) });
}
async function decryptSecret(env: Env, encrypted: string): Promise<string> {
  const record = JSON.parse(encrypted) as { iv: string; data: string };
  const raw = fromBase64(env.GOOGLE_TOKEN_ENCRYPTION_KEY);
  if (raw.length !== 32) throw new Error("Invalid token encryption key.");
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(raw), "AES-GCM", false, ["decrypt"]);
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(fromBase64(record.iv)) }, key, toArrayBuffer(fromBase64(record.data)));
  return decoder.decode(clear);
}
async function googleAccessToken(env: Env): Promise<string> {
  const encrypted = await env.OAUTH_KV.get("google:refresh-token");
  if (!encrypted) throw new Error("Google Blogger is not connected. Open /admin/google on your Worker URL and connect your Google account.");
  const refreshToken = await decryptSecret(env, encrypted);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });
  const data = await response.json() as { access_token?: string; error?: string; error_description?: string };
  if (!response.ok || !data.access_token) throw new Error(`Google token refresh failed: ${data.error_description ?? data.error ?? response.statusText}`);
  return data.access_token;
}
async function bloggerRequest(env: Env, path: string, init: RequestInit = {}): Promise<Json> {
  const token = await googleAccessToken(env);
  const response = await fetch(`https://www.googleapis.com/blogger/v3/${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers ?? {}) },
  });
  const body = await response.json().catch(() => ({})) as Json;
  if (!response.ok) {
    const error = body.error as Json | undefined;
    throw new Error(`Blogger API ${response.status}: ${String(error?.message ?? response.statusText)}`);
  }
  return body;
}
async function listBlogs(env: Env): Promise<Array<{ id: string; name: string; url: string; description?: string }>> {
  const body = await bloggerRequest(env, "users/self/blogs");
  const items = Array.isArray(body.items) ? body.items as Json[] : [];
  return items.map((item) => ({
    id: String(item.id ?? ""),
    name: String(item.name ?? "Untitled blog"),
    url: String(item.url ?? ""),
    ...(typeof item.description === "string" ? { description: item.description } : {}),
  })).filter((blog) => blog.id);
}
export function validatePostInput(input: Json): { blogId: string; title: string; content: string; labels: string[] } {
  const blogId = typeof input.blogId === "string" ? input.blogId.trim() : "";
  const title = typeof input.title === "string" ? input.title.trim() : "";
  const content = typeof input.content === "string" ? input.content.trim() : "";
  const labels = Array.isArray(input.labels) ? input.labels.map(String).map((s) => s.trim()).filter(Boolean) : [];
  if (!blogId) throw new Error("blogId is required. Use list_blogs to choose a blog.");
  if (!title || title.length > 200) throw new Error("title is required and must be at most 200 characters.");
  if (!content || content.length > 100_000) throw new Error("content is required and must be at most 100,000 characters of HTML.");
  if (labels.length > 20 || labels.some((label) => label.length > 200)) throw new Error("Provide at most 20 labels, each no longer than 200 characters.");
  return { blogId, title, content, labels };
}

const toolDefinitions = [
  {
    name: "list_blogs",
    description: "List the Blogger blogs available to the connected Google account. Call this first so the user can choose the destination blog by its exact blogId.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "publish_post",
    description: "Publish an article immediately (not as a draft) to the selected Blogger blog. Only call after the user has clearly asked to publish. Supply the exact blogId returned by list_blogs, an article title, and complete Blogger-compatible HTML content. Optional labels become Blogger labels. Returns the live post URL.",
    inputSchema: {
      type: "object",
      properties: {
        blogId: { type: "string", description: "Exact Blogger blog ID returned by list_blogs." },
        title: { type: "string", minLength: 1, maxLength: 200 },
        content: { type: "string", minLength: 1, maxLength: 100000, description: "Complete article body as Blogger-compatible HTML." },
        labels: { type: "array", items: { type: "string", maxLength: 200 }, maxItems: 20 },
      },
      required: ["blogId", "title", "content"],
      additionalProperties: false,
    },
  },
  {
    name: "get_post",
    description: "Retrieve a Blogger post and verify its published URL and status using its blogId and postId.",
    inputSchema: {
      type: "object",
      properties: { blogId: { type: "string" }, postId: { type: "string" } },
      required: ["blogId", "postId"],
      additionalProperties: false,
    },
  },
];

async function callTool(name: string, args: Json, env: Env): Promise<Json> {
  if (name === "list_blogs") {
    const blogs = await listBlogs(env);
    return { blogs, count: blogs.length, instruction: "Ask the user which blog to use, then pass its exact id to publish_post." };
  }
  if (name === "publish_post") {
    const post = validatePostInput(args);
    const blogs = await listBlogs(env);
    const selected = blogs.find((blog) => blog.id === post.blogId);
    if (!selected) throw new Error("The selected blogId is not accessible to the connected Google account. Call list_blogs again.");
    const result = await bloggerRequest(env, `blogs/${encodeURIComponent(post.blogId)}/posts?isDraft=false`, {
      method: "POST",
      body: JSON.stringify({
        kind: "blogger#post",
        title: post.title,
        content: post.content,
        ...(post.labels.length ? { labels: post.labels } : {}),
      }),
    });
    return {
      success: true,
      published: true,
      blog: { id: selected.id, name: selected.name, url: selected.url },
      post: { id: String(result.id ?? ""), title: String(result.title ?? post.title), url: String(result.url ?? ""), published: result.published ?? null, status: result.status ?? "LIVE" },
      message: "Blogger accepted the post for immediate publication.",
    };
  }
  if (name === "get_post") {
    const blogId = typeof args.blogId === "string" ? args.blogId.trim() : "";
    const postId = typeof args.postId === "string" ? args.postId.trim() : "";
    if (!blogId || !postId) throw new Error("blogId and postId are required.");
    const result = await bloggerRequest(env, `blogs/${encodeURIComponent(blogId)}/posts/${encodeURIComponent(postId)}`);
    return { id: result.id, title: result.title, url: result.url, published: result.published, status: result.status };
  }
  throw new Error(`Unknown tool: ${name}`);
}

async function mcp(request: Request, env: Env): Promise<Response> {
  const origin = originOf(request);
  const auth = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match) return unauthorized(origin);
  const session = await env.OAUTH_KV.get(`access:${match[1]}`, "json") as { expiresAt: number; scope: string } | null;
  if (!session || session.expiresAt < Date.now() / 1000 || !session.scope.split(" ").includes(MCP_SCOPE)) return unauthorized(origin);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  let payload: Json;
  try { payload = await request.json() as Json; } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const id = payload.id ?? null;
  const method = String(payload.method ?? "");
  if (method === "notifications/initialized" || method.startsWith("notifications/")) return new Response(null, { status: 202 });
  if (method === "initialize") {
    return json({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: { tools: {} },
        serverInfo: { name: "blogger-auto-publisher", version: "1.0.0" },
        instructions: "List the user's blogs before publishing. Publishing is immediate and public. Only publish when the user explicitly requests publication.",
      },
    });
  }
  if (method === "ping") return json({ jsonrpc: "2.0", id, result: {} });
  if (method === "tools/list") return json({ jsonrpc: "2.0", id, result: { tools: toolDefinitions } });
  if (method === "tools/call") {
    const params = (payload.params ?? {}) as Json;
    const name = String(params.name ?? "");
    const args = (params.arguments ?? {}) as Json;
    try {
      const result = await callTool(name, args, env);
      return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result } });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unexpected tool error";
      return json({ jsonrpc: "2.0", id, result: { isError: true, content: [{ type: "text", text: message }] } });
    }
  }
  return json({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } }, 404);
}

async function oauthMetadata(request: Request): Promise<Response> {
  const origin = originOf(request);
  const path = new URL(request.url).pathname;
  if (path === "/.well-known/oauth-protected-resource") return json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: [MCP_SCOPE],
  });
  return json({
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [MCP_SCOPE],
  });
}
async function registerClient(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as Json;
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((v): v is string => typeof v === "string") : [];
  if (!redirectUris.length || redirectUris.length > 10) return json({ error: "invalid_redirect_uri" }, 400);
  for (const value of redirectUris) {
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" && !(url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1"))) throw new Error();
    } catch { return json({ error: "invalid_redirect_uri", error_description: "Redirect URIs must use HTTPS, except localhost development callbacks." }, 400); }
  }
  const clientId = randomToken(24);
  await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify({ redirectUris, name: String(body.client_name ?? "MCP Client").slice(0, 100) }));
  return json({
    client_id: clientId,
    client_name: String(body.client_name ?? "MCP Client"),
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  }, 201);
}
async function authorizeGet(request: Request, env: Env): Promise<Response> {
  const u = new URL(request.url);
  const clientId = u.searchParams.get("client_id") ?? "";
  const redirectUri = u.searchParams.get("redirect_uri") ?? "";
  const state = u.searchParams.get("state") ?? "";
  const challenge = u.searchParams.get("code_challenge") ?? "";
  const method = u.searchParams.get("code_challenge_method") ?? "";
  const client = await env.OAUTH_KV.get(`client:${clientId}`, "json") as { redirectUris: string[] } | null;
  if (!client || !client.redirectUris.includes(redirectUri) || !state || !challenge || method !== "S256") return json({ error: "invalid_request" }, 400);
  return html(formPage("Connect Blogger Auto Publisher", "/oauth/authorize", {
    client_id: clientId, redirect_uri: redirectUri, state, code_challenge: challenge, code_challenge_method: method, scope: u.searchParams.get("scope") ?? MCP_SCOPE,
  }, "Authorize ChatGPT to list your Blogger blogs and publish articles when you explicitly ask it to."));
}
async function authorizePost(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const supplied = String(form.get("password") ?? "");
  if (!env.MCP_LOGIN_PASSWORD || !constantTimeEqual(supplied, env.MCP_LOGIN_PASSWORD)) return html("<h1>Access denied</h1><p>Incorrect password. Return to ChatGPT and try again.</p>", 401);
  const clientId = String(form.get("client_id") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const state = String(form.get("state") ?? "");
  const challenge = String(form.get("code_challenge") ?? "");
  const method = String(form.get("code_challenge_method") ?? "");
  const client = await env.OAUTH_KV.get(`client:${clientId}`, "json") as { redirectUris: string[] } | null;
  if (!client || !client.redirectUris.includes(redirectUri) || !state || !challenge || method !== "S256") return json({ error: "invalid_request" }, 400);
  const code = randomToken();
  await env.OAUTH_KV.put(`code:${code}`, JSON.stringify({ clientId, redirectUri, challenge, scope: MCP_SCOPE }), { expirationTtl: 300 });
  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  target.searchParams.set("state", state);
  return Response.redirect(target.toString(), 302);
}
async function tokenEndpoint(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const grant = String(form.get("grant_type") ?? "");
  const clientId = String(form.get("client_id") ?? "");
  const client = await env.OAUTH_KV.get(`client:${clientId}`, "json");
  if (!client) return json({ error: "invalid_client" }, 401);
  if (grant === "authorization_code") {
    const code = String(form.get("code") ?? "");
    const verifier = String(form.get("code_verifier") ?? "");
    const saved = await env.OAUTH_KV.get(`code:${code}`, "json") as { clientId: string; redirectUri: string; challenge: string; scope: string } | null;
    if (!saved || saved.clientId !== clientId || saved.redirectUri !== String(form.get("redirect_uri") ?? "") || !constantTimeEqual(await sha256(verifier), saved.challenge)) return json({ error: "invalid_grant" }, 400);
    await env.OAUTH_KV.delete(`code:${code}`);
    return issueTokens(env, clientId, saved.scope);
  }
  if (grant === "refresh_token") {
    const old = String(form.get("refresh_token") ?? "");
    const saved = await env.OAUTH_KV.get(`refresh:${old}`, "json") as { clientId: string; scope: string } | null;
    if (!saved || saved.clientId !== clientId) return json({ error: "invalid_grant" }, 400);
    await env.OAUTH_KV.delete(`refresh:${old}`);
    return issueTokens(env, clientId, saved.scope);
  }
  return json({ error: "unsupported_grant_type" }, 400);
}
async function issueTokens(env: Env, clientId: string, scope: string): Promise<Response> {
  const access = randomToken();
  const refresh = randomToken();
  await env.OAUTH_KV.put(`access:${access}`, JSON.stringify({ clientId, scope, expiresAt: Math.floor(Date.now() / 1000) + ACCESS_TTL }), { expirationTtl: ACCESS_TTL });
  await env.OAUTH_KV.put(`refresh:${refresh}`, JSON.stringify({ clientId, scope }), { expirationTtl: REFRESH_TTL });
  return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refresh, scope });
}
async function googleConnectGet(): Promise<Response> {
  return html(formPage("Connect your Google Blogger account", "/admin/google", {}, "Enter your administrator password to begin Google OAuth. You will then grant Blogger access on Google's own consent screen."));
}
async function googleConnectPost(request: Request, env: Env): Promise<Response> {
  if (!(await requireAdmin(request, env))) return html("<h1>Access denied</h1><p>Incorrect administrator password.</p>", 401);
  const state = randomToken();
  await env.OAUTH_KV.put(`google:state:${state}`, "1", { expirationTtl: 600 });
  const redirectUri = `${originOf(request)}/oauth/google/callback`;
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: GOOGLE_SCOPE,
    access_type: "offline",
    prompt: "consent",
    state,
  }).toString();
  return Response.redirect(url.toString(), 302);
}
async function googleCallback(request: Request, env: Env): Promise<Response> {
  const u = new URL(request.url);
  const state = u.searchParams.get("state") ?? "";
  const validState = await env.OAUTH_KV.get(`google:state:${state}`);
  if (!state || !validState) return json({ error: "invalid_oauth_state" }, 400);
  await env.OAUTH_KV.delete(`google:state:${state}`);
  if (u.searchParams.has("error")) return html(`<h1>Google authorization failed</h1><p>${escapeHtml(u.searchParams.get("error_description") ?? u.searchParams.get("error") ?? "Unknown error")}</p>`, 400);
  const code = u.searchParams.get("code");
  if (!code) return json({ error: "missing_code" }, 400);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${originOf(request)}/oauth/google/callback`,
      grant_type: "authorization_code",
    }),
  });
  const data = await response.json() as { refresh_token?: string; error?: string; error_description?: string };
  if (!response.ok || !data.refresh_token) return html(`<h1>Google connection not completed</h1><p>${escapeHtml(data.error_description ?? data.error ?? "Google did not return a refresh token. Revoke previous consent and retry.")}</p>`, 400);
  await env.OAUTH_KV.put("google:refresh-token", await encryptSecret(env, data.refresh_token));
  return html("<h1>Google Blogger connected</h1><p>Your refresh token is encrypted before being stored. You can now connect this MCP server to ChatGPT and publish articles.</p><p><a href='/health'>Check service status</a></p>");
}
async function adminStatus(request: Request, env: Env): Promise<Response> {
  const connected = Boolean(await env.OAUTH_KV.get("google:refresh-token"));
  const origin = originOf(request);
  return html(`<!doctype html><meta charset="utf-8"><title>Blogger Auto Publisher</title><main style="font:16px system-ui;max-width:680px;margin:48px auto;padding:20px"><h1>Blogger Auto Publisher</h1><p>Google Blogger: <strong>${connected ? "Connected" : "Not connected"}</strong></p><p>MCP endpoint: <code>${escapeHtml(origin)}/mcp</code></p><p><a href="/admin/google">Connect or reconnect Google</a></p><p>OAuth metadata: <a href="/.well-known/oauth-authorization-server">authorization server</a></p></main>`);
}

async function publishPage(request: Request, env: Env): Promise<Response> {
  const cookie = request.headers.get("cookie") ?? "";
  const token = cookie.match(/(?:^|;\\s*)bap_session=([a-f0-9]{64})(?:;|$)/)?.[1] ?? "";
  const session = token ? await env.OAUTH_KV.get(`publish-session:${token}`, "json") as { csrf: string } | null : null;
  const page = (body: string, status = 200, headers: HeadersInit = {}) =>
    new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers } });
  const shell = (title: string, body: string) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>
  *{box-sizing:border-box}body{margin:0;background:#f3f6fb;color:#172033;font:16px system-ui;line-height:1.5}main{width:min(820px,calc(100% - 28px));margin:36px auto;background:#fff;padding:clamp(20px,4vw,36px);border-radius:18px;box-shadow:0 12px 40px #17203314}h1{font-size:26px;margin:0 0 8px}p{color:#5b6678}label{display:block;font-weight:650;margin:18px 0 7px}input,textarea,select{width:100%;padding:12px;border:1px solid #cbd3df;border-radius:9px;font:inherit;background:white}textarea{min-height:260px;resize:vertical}button{margin-top:20px;padding:13px 20px;border:0;border-radius:9px;background:#1769e0;color:white;font:inherit;font-weight:700;cursor:pointer}.muted{font-size:13px;color:#68758a}.success{padding:14px;border-radius:10px;background:#eaf8ef;color:#176b38}a{color:#1769e0}</style><main>${body}</main></html>`;
  if (request.method === "GET") {
    if (!session) return page(shell("Blogger Auto Publisher", `<h1>Blogger Auto Publisher</h1><p>Sign in to the private publishing page using your Worker administrator password.</p><form method="post" action="/admin/publish"><label>Administrator password</label><input name="password" type="password" required autocomplete="current-password"><button type="submit">Continue</button></form><p class="muted">Your password is checked by this Worker. It is not stored in the browser.</p>`));
    try {
      const blogs = await listBlogs(env);
      const options = blogs.map((blog) => `<option value="${escapeHtml(blog.id)}">${escapeHtml(blog.name)} — ${escapeHtml(blog.url)}</option>`).join("");
      const body = `<h1>Publish to Blogger</h1><p>Select a blog, add your article, and publish when ready. Publishing is immediate and public.</p>
      ${blogs.length ? `<form method="post" action="/admin/publish"><input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}"><label>Destination blog</label><select name="blogId" required>${options}</select><label>Article title</label><input name="title" maxlength="200" required><label>Article content (HTML)</label><textarea name="content" maxlength="100000" required placeholder="<h2>Article heading</h2>\n<p>Your article...</p>"></textarea><label>Labels (comma-separated, optional)</label><input name="labels" placeholder="SEO, Blogger, Guides"><button type="submit">Publish article now</button></form>` : "<p>No Blogger blogs were found for the connected Google account.</p>"}<form method="post" action="/admin/publish/logout"><input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}"><button type="submit" style="background:#68758a">Sign out</button></form><p class="muted">Connected Google account access is stored encrypted in Cloudflare KV.</p>`;
      return page(shell("Publish to Blogger", body));
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to load Blogger blogs.";
      return page(shell("Blogger connection error", `<h1>Unable to load blogs</h1><p>${escapeHtml(message)}</p><p><a href="/admin">Return to service status</a></p>`), 502);
    }
  }
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const origin = request.headers.get("origin");
  if (origin && origin !== originOf(request)) return json({ error: "origin_forbidden" }, 403);
  const form = await request.formData();
  if (new URL(request.url).pathname.endsWith("/logout")) {
    if (!session || !constantTimeEqual(String(form.get("csrf") ?? ""), session.csrf)) return page(shell("Session expired", "<h1>Session expired</h1><p>Return to the publishing page and sign in again.</p>"), 403, { "set-cookie": "bap_session=; Path=/admin/publish; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
    await env.OAUTH_KV.delete(`publish-session:${token}`);
    return page(shell("Signed out", '<h1>You are signed out</h1><p><a href="/admin/publish">Return to sign in</a></p>'), 200, { "set-cookie": "bap_session=; Path=/admin/publish; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  if (!session) {
    const supplied = String(form.get("password") ?? "");
    if (!env.MCP_LOGIN_PASSWORD || !constantTimeEqual(supplied, env.MCP_LOGIN_PASSWORD)) return page(shell("Access denied", '<h1>Access denied</h1><p>Incorrect administrator password.</p><p><a href="/admin/publish">Try again</a></p>'), 401);
    const newToken = randomToken();
    const csrf = randomToken();
    await env.OAUTH_KV.put(`publish-session:${newToken}`, JSON.stringify({ csrf }), { expirationTtl: 1800 });
    return new Response(null, { status: 303, headers: { location: "/admin/publish", "cache-control": "no-store", "set-cookie": `bap_session=${newToken}; Path=/admin/publish; HttpOnly; Secure; SameSite=Strict; Max-Age=1800` } });
  }
  if (!constantTimeEqual(String(form.get("csrf") ?? ""), session.csrf)) return page(shell("Request rejected", "<h1>Request rejected</h1><p>Security token did not match. Reload the page and try again.</p>"), 403);
  try {
    const labels = String(form.get("labels") ?? "").split(",").map((label) => label.trim()).filter(Boolean);
    const post = validatePostInput({ blogId: String(form.get("blogId") ?? ""), title: String(form.get("title") ?? ""), content: String(form.get("content") ?? ""), labels });
    const result = await callTool("publish_post", post as unknown as Json, env);
    const published = result.post as Json;
    const url = typeof published?.url === "string" ? published.url : "";
    return page(shell("Article published", `<h1>Article published</h1><p class="success">Blogger accepted your article for publication.</p><p><strong>${escapeHtml(String(published?.title ?? post.title))}</strong></p>${url ? `<p><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Open published article</a></p>` : ""}<p><a href="/admin/publish">Publish another article</a></p>`));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Publication failed.";
    return page(shell("Publication failed", `<h1>Publication failed</h1><p>${escapeHtml(message)}</p><p><a href="/admin/publish">Return to the publishing form</a></p>`), 400);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "OPTIONS") return withCors(new Response(null, { status: 204 }));
      if (url.pathname === "/health") return json({ ok: true, service: "blogger-auto-publisher", version: "1.0.0" });
      if (url.pathname === "/.well-known/oauth-protected-resource") return oauthMetadata(request);
      if (url.pathname === "/.well-known/oauth-authorization-server") return oauthMetadata(request);
      if (url.pathname === "/oauth/register" && request.method === "POST") return oauthMetadataRegister(request, env);
      if (url.pathname === "/oauth/authorize" && request.method === "GET") return authorizeGet(request, env);
      if (url.pathname === "/oauth/authorize" && request.method === "POST") return authorizePost(request, env);
      if (url.pathname === "/oauth/token" && request.method === "POST") return tokenEndpoint(request, env);
      if (url.pathname === "/admin" && request.method === "GET") return adminStatus(request, env);
      if (url.pathname === "/admin/publish") return publishPage(request, env);
      if (url.pathname === "/admin/google" && request.method === "GET") return googleConnectGet();
      if (url.pathname === "/admin/google" && request.method === "POST") return googleConnectPost(request, env);
      if (url.pathname === "/oauth/google/callback" && request.method === "GET") return googleCallback(request, env);
      if (url.pathname === "/mcp") return withCors(await mcp(request, env));
      return json({ error: "not_found" }, 404);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal server error";
      return json({ error: "server_error", message }, 500);
    }
  },
};
async function oauthMetadataRegister(request: Request, env: Env): Promise<Response> {
  return registerClient(request, env);
}
