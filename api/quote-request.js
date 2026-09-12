/**
 * Quote request intake for barn-beam.com
 *
 * POST  /api/quote-request   — public form intake (honeypot protected)
 * GET   /api/quote-request   — list (Authorization: Bearer QUOTE_API_SECRET)
 * PATCH /api/quote-request   — update status (Authorization: Bearer QUOTE_API_SECRET)
 *
 * Storage: Vercel Blob (enable Blob on the project; BLOB_READ_WRITE_TOKEN is injected).
 * Set QUOTE_API_SECRET in Vercel env to the same secret shown in the Job Calculator settings.
 */

const { put, list, del } = require("@vercel/blob");

const PREFIX = "quote-requests/";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function getSecret() {
  return (process.env.QUOTE_API_SECRET || "").trim();
}

function authorized(req) {
  const secret = getSecret();
  if (!secret) return false;
  const header = req.headers.authorization || req.headers.Authorization || "";
  const m = String(header).match(/^Bearer\s+(.+)$/i);
  if (m && m[1].trim() === secret) return true;
  // Also allow ?secret= for simple tools
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.searchParams.get("secret") === secret) return true;
  } catch (_) {
    /* ignore */
  }
  return false;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 200_000) {
        reject(new Error("Body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (_) {
        // form-urlencoded fallback
        try {
          const params = new URLSearchParams(data);
          const obj = {};
          params.forEach((v, k) => {
            obj[k] = v;
          });
          resolve(obj);
        } catch (e) {
          reject(e);
        }
      }
    });
    req.on("error", reject);
  });
}

function cleanText(v, max = 4000) {
  return String(v ?? "")
    .replace(/\0/g, "")
    .trim()
    .slice(0, max);
}

function newId() {
  return (
    "qr_" +
    Date.now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 10)
  );
}

async function listRequests() {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return { items: [], storage: "none" };
  }
  const result = await list({ prefix: PREFIX, limit: 500 });
  const blobs = (result.blobs || []).filter((b) => b.pathname.endsWith(".json"));
  const items = [];
  for (const b of blobs) {
    try {
      const res = await fetch(b.url, { cache: "no-store" });
      if (!res.ok) continue;
      const item = await res.json();
      if (item && item.id) items.push(item);
    } catch (_) {
      /* skip bad blob */
    }
  }
  items.sort((a, b) => String(b.submitted_at || "").localeCompare(String(a.submitted_at || "")));
  return { items, storage: "blob" };
}

async function saveRequest(item) {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    const err = new Error(
      "Vercel Blob is not configured. In Vercel → Storage → create a Blob store and connect this project."
    );
    err.code = "NO_BLOB";
    throw err;
  }
  const path = `${PREFIX}${item.id}.json`;
  await put(path, JSON.stringify(item, null, 2), {
    access: "public",
    contentType: "application/json",
    addRandomSuffix: false,
    allowOverwrite: true,
  });
  return item;
}

async function deleteRequest(id) {
  if (!process.env.BLOB_READ_WRITE_TOKEN) return;
  const path = `${PREFIX}${id}.json`;
  try {
    await del(path);
  } catch (_) {
    // Older SDKs may need full URL — list and delete
    const { blobs } = await list({ prefix: `${PREFIX}${id}`, limit: 5 });
    for (const b of blobs || []) {
      try {
        await del(b.url);
      } catch (_) {
        /* ignore */
      }
    }
  }
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  try {
    if (req.method === "POST") {
      const body = await readBody(req);

      // Honeypot
      if (body._honey || body.honey || body.website_url) {
        return json(res, 200, { ok: true, ignored: true });
      }

      const name = cleanText(body.name, 120);
      const email = cleanText(body.email, 200).toLowerCase();
      const phone = cleanText(body.phone, 40);
      const service = cleanText(body.service, 120);
      const message = cleanText(body.message, 4000);

      if (!name || !email || !message) {
        return json(res, 400, {
          ok: false,
          error: "Name, email, and project notes are required.",
        });
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json(res, 400, { ok: false, error: "Invalid email address." });
      }

      // Optional pre-scanned attachment from /api/quote-upload
      let attachment = null;
      if (body.attachment && typeof body.attachment === "object") {
        const a = body.attachment;
        const attId = cleanText(a.id, 80);
        const pathname = cleanText(a.pathname, 300);
        const filename = cleanText(a.filename, 160);
        if (
          attId.startsWith("att_") &&
          pathname.startsWith("quote-files/") &&
          a.scan &&
          String(a.scan.status || "") === "clean"
        ) {
          attachment = {
            id: attId,
            pathname,
            filename: filename || "artwork",
            size: Number(a.size) || 0,
            contentType: cleanText(a.contentType, 80),
            sha256: cleanText(a.sha256, 80),
            url: cleanText(a.url, 500),
            downloadUrl: cleanText(a.downloadUrl || a.url, 500),
            scan: {
              status: "clean",
              provider: cleanText(a.scan.provider, 40) || "virustotal",
              malicious: 0,
              suspicious: 0,
              engineCount: Number(a.scan.engineCount) || 0,
            },
            uploaded_at: cleanText(a.uploaded_at, 40),
          };
        }
      }

      const item = {
        id: newId(),
        name,
        email,
        phone: phone && phone !== "Not provided" ? phone : "",
        service: service && service !== "Not specified" ? service : "",
        message,
        attachment,
        source: "website",
        status: "needed",
        submitted_at: new Date().toISOString(),
        user_agent: cleanText(req.headers["user-agent"], 300),
        page: cleanText(body.page || body._url || "", 300),
      };

      try {
        await saveRequest(item);
      } catch (e) {
        if (e.code === "NO_BLOB") {
          return json(res, 503, {
            ok: false,
            error: e.message,
            hint: "Enable Vercel Blob on this project, then redeploy.",
          });
        }
        throw e;
      }

      return json(res, 201, { ok: true, id: item.id });
    }

    if (req.method === "GET") {
      if (!authorized(req)) {
        return json(res, 401, {
          ok: false,
          error: "Unauthorized. Set QUOTE_API_SECRET in Vercel and use Bearer token.",
        });
      }
      const { items, storage } = await listRequests();
      return json(res, 200, {
        ok: true,
        storage,
        count: items.length,
        items,
      });
    }

    if (req.method === "PATCH") {
      if (!authorized(req)) {
        return json(res, 401, { ok: false, error: "Unauthorized" });
      }
      const body = await readBody(req);
      const id = cleanText(body.id, 80);
      if (!id) return json(res, 400, { ok: false, error: "id required" });

      const { items } = await listRequests();
      const existing = items.find((x) => x.id === id);
      if (!existing) return json(res, 404, { ok: false, error: "Not found" });

      if (body.status === "deleted" || body.delete) {
        await deleteRequest(id);
        return json(res, 200, { ok: true, deleted: true });
      }

      const next = {
        ...existing,
        status: cleanText(body.status || existing.status, 40) || existing.status,
        updated_at: new Date().toISOString(),
      };
      if (body.job_id != null) next.job_id = body.job_id;
      await saveRequest(next);
      return json(res, 200, { ok: true, item: next });
    }

    return json(res, 405, { ok: false, error: "Method not allowed" });
  } catch (err) {
    console.error("quote-request error", err);
    return json(res, 500, {
      ok: false,
      error: err.message || "Server error",
    });
  }
};
