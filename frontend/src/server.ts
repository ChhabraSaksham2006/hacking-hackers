import "./lib/error-capture";

import { consumeLastCapturedError } from "./lib/error-capture";
import { renderErrorPage } from "./lib/error-page";

type ServerEntry = {
  fetch: (request: Request, env: unknown, ctx: unknown) => Promise<Response> | Response;
};

let serverEntryPromise: Promise<ServerEntry> | undefined;

async function getServerEntry(): Promise<ServerEntry> {
  if (!serverEntryPromise) {
    serverEntryPromise = import("@tanstack/react-start/server-entry").then(
      (m) => (m.default ?? m) as ServerEntry,
    );
  }
  return serverEntryPromise;
}

// h3 swallows in-handler throws into a normal 500 Response with body
// {"unhandled":true,"message":"HTTPError"} — try/catch alone never fires for those.
async function normalizeCatastrophicSsrResponse(response: Response): Promise<Response> {
  if (response.status < 500) return response;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  const body = await response.clone().text();
  if (!isH3SwallowedErrorBody(body)) return response;

  console.error(consumeLastCapturedError() ?? new Error(`h3 swallowed SSR error: ${body}`));
  return new Response(renderErrorPage(), {
    status: 500,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function isH3SwallowedErrorBody(body: string): boolean {
  try {
    const payload = JSON.parse(body) as { unhandled?: unknown; message?: unknown };
    return payload.unhandled === true && payload.message === "HTTPError";
  } catch {
    return false;
  }
}

async function proxyToBackend(request: Request, url: URL): Promise<Response> {
  const backendBase =
    process.env["BACKEND_URL"] ||
    (process.env["NODE_ENV"] === "production"
      ? "https://hacking-hackers-backend.onrender.com"
      : "http://localhost:5000");

  const targetUrl = new URL(url.pathname + url.search, backendBase);

  const headers = new Headers(request.headers);
  headers.set("host", targetUrl.host);
  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: "manual",
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    // @ts-expect-error duplex is required in Node.js fetch for stream bodies
    init.duplex = "half";
    init.body = request.body;
  }

  try {
    const backendRes = await fetch(targetUrl.toString(), init);

    const resHeaders = new Headers(backendRes.headers);

    // Node 18+ provides getSetCookie() to accurately preserve multiple Set-Cookie headers
    if (typeof backendRes.headers.getSetCookie === "function") {
      resHeaders.delete("set-cookie");
      for (const cookie of backendRes.headers.getSetCookie()) {
        resHeaders.append("set-cookie", cookie);
      }
    }

    return new Response(backendRes.body, {
      status: backendRes.status,
      statusText: backendRes.statusText,
      headers: resHeaders,
    });
  } catch (err) {
    console.error(
      `[Proxy Error] Failed to forward ${request.method} ${url.pathname} to ${targetUrl}:`,
      err,
    );
    return new Response(
      JSON.stringify({
        error: "Backend Unavailable",
        message: "Failed to connect to Aegis Vantage backend server on port 5000.",
        target: targetUrl.toString(),
      }),
      {
        status: 502,
        headers: { "content-type": "application/json" },
      },
    );
  }
}

export default {
  async fetch(request: Request, env: unknown, ctx: unknown) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api") || url.pathname.startsWith("/socket.io")) {
      return await proxyToBackend(request, url);
    }
    try {
      const handler = await getServerEntry();
      const response = await handler.fetch(request, env, ctx);
      return await normalizeCatastrophicSsrResponse(response);
    } catch (error) {
      console.error(error);
      return new Response(renderErrorPage(), {
        status: 500,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
  },
};
