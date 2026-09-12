/**
 * Secure artwork upload for quote requests.
 *
 * POST /api/quote-upload  (multipart: file field "file" or "artwork")
 *
 * Pipeline:
 *  1) Size / type allowlist
 *  2) Magic-byte content verification
 *  3) VirusTotal malware scan (VIRUSTOTAL_API_KEY required)
 *  4) Store in private Vercel Blob only if clean
 *
 * Returns attachment metadata for the quote-request form.
 */

const { put } = require("@vercel/blob");
const Busboy = require("busboy");
const {
  MAX_BYTES,
  sanitizeFilename,
  validateBuffer,
  scanWithVirusTotal,
} = require("./lib/file-security");

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function newAttachmentId() {
  return (
    "att_" +
    Date.now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 10)
  );
}

function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const bb = Busboy({
      headers: req.headers,
      limits: {
        files: 1,
        fileSize: MAX_BYTES + 1024,
        fields: 10,
      },
    });

    let fileInfo = null;
    const chunks = [];
    let truncated = false;
    let settled = false;

    bb.on("file", (name, stream, info) => {
      if (fileInfo) {
        stream.resume();
        return;
      }
      fileInfo = {
        field: name,
        filename: info.filename || "upload.bin",
        mimeType: info.mimeType || info.mime || "",
      };
      stream.on("data", (d) => chunks.push(d));
      stream.on("limit", () => {
        truncated = true;
      });
      stream.on("error", reject);
    });

    bb.on("error", reject);
    bb.on("finish", () => {
      if (settled) return;
      settled = true;
      if (!fileInfo) {
        return resolve({ error: "No file uploaded. Use field name \"file\" or \"artwork\"." });
      }
      if (truncated) {
        return resolve({
          error: `File too large. Maximum size is ${Math.floor(MAX_BYTES / (1024 * 1024))} MB.`,
        });
      }
      const buffer = Buffer.concat(chunks);
      resolve({ fileInfo, buffer });
    });

    req.pipe(bb);
  });
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== "POST") {
    return json(res, 405, { ok: false, error: "Method not allowed" });
  }

  try {
    if (!process.env.BLOB_READ_WRITE_TOKEN) {
      return json(res, 503, {
        ok: false,
        error: "File storage is not configured (Vercel Blob).",
      });
    }

    const vtKey = (process.env.VIRUSTOTAL_API_KEY || "").trim();
    if (!vtKey) {
      return json(res, 503, {
        ok: false,
        error:
          "Malware scanning is not configured. Add VIRUSTOTAL_API_KEY in Vercel environment variables.",
        hint: "Create a free API key at https://www.virustotal.com/gui/my-apikey",
      });
    }

    const parsed = await parseMultipart(req);
    if (parsed.error) {
      return json(res, 400, { ok: false, error: parsed.error });
    }

    const { fileInfo, buffer } = parsed;
    const safeName = sanitizeFilename(fileInfo.filename);
    const validation = validateBuffer(buffer, safeName, fileInfo.mimeType);
    if (!validation.ok) {
      return json(res, 400, { ok: false, error: validation.error });
    }

    // Normalize filename extension to detected type
    const finalName = safeName.includes(".")
      ? safeName.replace(/\.[^.]+$/, validation.ext)
      : safeName + validation.ext;

    let scan;
    try {
      scan = await scanWithVirusTotal(buffer, finalName, vtKey);
    } catch (e) {
      const status =
        e.code === "VT_RATE" ? 429 : e.code === "VT_TIMEOUT" ? 504 : 502;
      return json(res, status, {
        ok: false,
        error: e.message || "Malware scan failed",
        code: e.code || "VT_ERROR",
      });
    }

    if (!scan.ok) {
      return json(res, 400, {
        ok: false,
        error:
          "This file was blocked by security scanning and was not uploaded.",
        scan: {
          status: scan.status,
          malicious: scan.malicious,
          suspicious: scan.suspicious,
          provider: scan.provider,
        },
      });
    }

    const attachmentId = newAttachmentId();
    const pathname = `quote-files/${attachmentId}/${finalName}`;

    // Private blob — not publicly listable; download requires authenticated API
    const stored = await put(pathname, buffer, {
      access: "private",
      contentType: validation.contentType,
      addRandomSuffix: false,
      allowOverwrite: false,
    });

    const attachment = {
      id: attachmentId,
      pathname: stored.pathname || pathname,
      url: stored.url || "",
      downloadUrl: stored.downloadUrl || stored.url || "",
      filename: finalName,
      size: validation.size,
      contentType: validation.contentType,
      sha256: validation.sha256,
      scan: {
        status: "clean",
        provider: scan.provider,
        malicious: 0,
        suspicious: 0,
        engineCount: scan.engineCount || 0,
        source: scan.source || "upload",
      },
      uploaded_at: new Date().toISOString(),
    };

    return json(res, 201, { ok: true, attachment });
  } catch (err) {
    console.error("quote-upload error", err);
    return json(res, 500, {
      ok: false,
      error: err.message || "Upload failed",
    });
  }
};

// Disable default body parsing so Busboy can read the stream
module.exports.config = {
  api: {
    bodyParser: false,
  },
};
