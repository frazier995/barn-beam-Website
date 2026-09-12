/**
 * Authenticated download of private quote artwork.
 *
 * GET /api/quote-attachment?id=att_xxx&pathname=quote-files/...
 * Authorization: Bearer QUOTE_API_SECRET
 */

const { get, list, head } = require("@vercel/blob");

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function authorized(req) {
  const secret = (process.env.QUOTE_API_SECRET || "").trim();
  if (!secret) return false;
  const header = req.headers.authorization || "";
  const m = String(header).match(/^Bearer\s+(.+)$/i);
  if (m && m[1].trim() === secret) return true;
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.searchParams.get("secret") === secret) return true;
  } catch (_) {
    /* ignore */
  }
  return false;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== "GET") {
    return json(res, 405, { ok: false, error: "Method not allowed" });
  }
  if (!authorized(req)) {
    return json(res, 401, { ok: false, error: "Unauthorized" });
  }

  try {
    const url = new URL(req.url, "http://localhost");
    let pathname = (url.searchParams.get("pathname") || "").trim();
    const id = (url.searchParams.get("id") || "").trim();

    if (!pathname && id) {
      // Resolve by attachment id prefix
      const listed = await list({ prefix: `quote-files/${id}/`, limit: 5 });
      const blob = (listed.blobs || [])[0];
      if (!blob) return json(res, 404, { ok: false, error: "Attachment not found" });
      pathname = blob.pathname;
    }

    if (!pathname || !pathname.startsWith("quote-files/")) {
      return json(res, 400, { ok: false, error: "Invalid attachment path" });
    }

    // Prefer streaming via get(); fall back to redirect to signed URL if available
    try {
      const result = await get(pathname, { access: "private" });
      if (result && result.stream) {
        const meta = await head(pathname).catch(() => null);
        res.statusCode = 200;
        res.setHeader(
          "Content-Type",
          meta?.contentType || result.blob?.contentType || "application/octet-stream"
        );
        const filename = pathname.split("/").pop() || "attachment";
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${filename.replace(/"/g, "")}"`
        );
        res.setHeader("Cache-Control", "private, no-store");
        // Node stream pipe
        if (typeof result.stream.pipe === "function") {
          result.stream.pipe(res);
          return;
        }
        // Web ReadableStream
        const reader = result.stream.getReader();
        const pump = async () => {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            res.write(Buffer.from(value));
          }
          res.end();
        };
        await pump();
        return;
      }
    } catch (e) {
      console.warn("private get failed, trying list url", e.message);
    }

    const listed = await list({ prefix: pathname, limit: 5 });
    const blob = (listed.blobs || []).find((b) => b.pathname === pathname) || (listed.blobs || [])[0];
    if (!blob?.url) {
      return json(res, 404, { ok: false, error: "Attachment not found" });
    }

    // Return JSON with short-lived URL for the Hub to open/download
    return json(res, 200, {
      ok: true,
      url: blob.url,
      downloadUrl: blob.downloadUrl || blob.url,
      pathname: blob.pathname,
      size: blob.size,
      uploadedAt: blob.uploadedAt,
    });
  } catch (err) {
    console.error("quote-attachment error", err);
    return json(res, 500, { ok: false, error: err.message || "Download failed" });
  }
};
