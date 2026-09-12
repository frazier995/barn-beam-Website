/**
 * Secure upload helpers for quote artwork files.
 * - Extension + MIME allowlist
 * - Magic-byte (file signature) verification
 * - VirusTotal malware scan (requires VIRUSTOTAL_API_KEY)
 */

const crypto = require("crypto");

const MAX_BYTES = 4 * 1024 * 1024; // 4 MB (under Vercel body limit)

/** Allowed artwork types only — no executables, scripts, archives, or SVG */
const ALLOWED = {
  "application/pdf": {
    ext: [".pdf"],
    magic: [(buf) => buf.length >= 4 && buf.slice(0, 4).toString("ascii") === "%PDF"],
  },
  "image/jpeg": {
    ext: [".jpg", ".jpeg"],
    magic: [(buf) => buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff],
  },
  "image/png": {
    ext: [".png"],
    magic: [
      (buf) =>
        buf.length >= 8 &&
        buf[0] === 0x89 &&
        buf[1] === 0x50 &&
        buf[2] === 0x4e &&
        buf[3] === 0x47,
    ],
  },
  "image/webp": {
    ext: [".webp"],
    magic: [
      (buf) =>
        buf.length >= 12 &&
        buf.slice(0, 4).toString("ascii") === "RIFF" &&
        buf.slice(8, 12).toString("ascii") === "WEBP",
    ],
  },
  "image/gif": {
    ext: [".gif"],
    magic: [
      (buf) => {
        if (buf.length < 6) return false;
        const h = buf.slice(0, 6).toString("ascii");
        return h === "GIF87a" || h === "GIF89a";
      },
    ],
  },
};

function getExt(name) {
  const n = String(name || "").toLowerCase();
  const i = n.lastIndexOf(".");
  return i >= 0 ? n.slice(i) : "";
}

function sanitizeFilename(name) {
  const base = String(name || "file")
    .replace(/[/\\?%*:|"<>]/g, "_")
    .replace(/\s+/g, "_")
    .slice(0, 120);
  const ext = getExt(base);
  const stem = ext ? base.slice(0, -ext.length) : base;
  const cleanStem = (stem || "file").replace(/^\.+/, "") || "file";
  return cleanStem.slice(0, 80) + (ext || "");
}

function sniffContentType(buf, claimedType, filename) {
  const ext = getExt(filename);
  const candidates = Object.keys(ALLOWED).filter((mime) => {
    const rule = ALLOWED[mime];
    return rule.ext.includes(ext) || mime === claimedType;
  });
  const tryList = candidates.length
    ? candidates
    : Object.keys(ALLOWED);

  for (const mime of tryList) {
    const rule = ALLOWED[mime];
    if (rule.magic.some((fn) => fn(buf))) {
      // Prefer extension match when magic matches multiple (rare)
      if (rule.ext.includes(ext) || !ext) return mime;
      if (mime === claimedType) return mime;
    }
  }
  // Magic-only pass
  for (const mime of Object.keys(ALLOWED)) {
    if (ALLOWED[mime].magic.some((fn) => fn(buf))) return mime;
  }
  return null;
}

function validateBuffer(buf, filename, claimedType) {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) {
    return { ok: false, error: "Empty file." };
  }
  if (buf.length > MAX_BYTES) {
    return {
      ok: false,
      error: `File too large. Maximum size is ${Math.floor(MAX_BYTES / (1024 * 1024))} MB.`,
    };
  }

  // Block double extensions and obvious payloads
  const lower = String(filename || "").toLowerCase();
  if (/\.(exe|bat|cmd|com|msi|dll|js|mjs|cjs|html?|php|phtml|asp|aspx|jsp|sh|ps1|vbs|scr|jar|apk|dmg|pkg|iso|svg|zip|rar|7z|gz|tar|xz|docm|xlsm|pptm)$/i.test(lower)) {
    return { ok: false, error: "This file type is not allowed for security reasons." };
  }

  const detected = sniffContentType(buf, claimedType, filename);
  if (!detected) {
    return {
      ok: false,
      error:
        "File type not allowed or content does not match. Use PDF, JPG, PNG, WEBP, or GIF.",
    };
  }

  const rule = ALLOWED[detected];
  const ext = getExt(filename);
  if (ext && !rule.ext.includes(ext)) {
    // Allow if magic is solid but extension wrong — normalize extension
  }

  return {
    ok: true,
    contentType: detected,
    ext: rule.ext.includes(ext) ? ext : rule.ext[0],
    size: buf.length,
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
  };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Scan file with VirusTotal v3.
 * Returns { ok, status, malicious, suspicious, engineCount, id }
 */
async function scanWithVirusTotal(buf, filename, apiKey) {
  if (!apiKey) {
    const err = new Error(
      "Malware scanning is not configured. Set VIRUSTOTAL_API_KEY on the website project."
    );
    err.code = "NO_VT";
    throw err;
  }

  const headers = {
    "x-apikey": apiKey,
    Accept: "application/json",
  };

  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

  // 1) Known hash report (fast path)
  try {
    const known = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers,
    });
    if (known.status === 200) {
      const body = await known.json();
      const stats = body?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      if (malicious > 0 || suspicious > 0) {
        return {
          ok: false,
          status: "malicious",
          malicious,
          suspicious,
          engineCount: Object.values(stats).reduce((a, b) => a + Number(b || 0), 0),
          id: sha256,
          provider: "virustotal",
        };
      }
      return {
        ok: true,
        status: "clean",
        malicious: 0,
        suspicious: 0,
        engineCount: Object.values(stats).reduce((a, b) => a + Number(b || 0), 0),
        id: sha256,
        provider: "virustotal",
        source: "hash",
      };
    }
  } catch (_) {
    /* fall through to upload */
  }

  // 2) Upload for analysis
  const form = new FormData();
  const blob = new Blob([buf], { type: "application/octet-stream" });
  form.append("file", blob, filename || "upload.bin");

  const up = await fetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body: form,
  });

  if (up.status === 429) {
    const err = new Error("Scan service is busy. Please try again in a minute.");
    err.code = "VT_RATE";
    throw err;
  }
  if (!up.ok) {
    const t = await up.text();
    const err = new Error(`Scan service error (${up.status}). ${t.slice(0, 120)}`);
    err.code = "VT_UPLOAD";
    throw err;
  }

  const upBody = await up.json();
  const analysisId = upBody?.data?.id;
  if (!analysisId) {
    const err = new Error("Scan service did not return an analysis id.");
    err.code = "VT_UPLOAD";
    throw err;
  }

  // 3) Poll (keep under serverless time budget)
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    await sleep(1500);
    const an = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers,
    });
    if (!an.ok) continue;
    const anBody = await an.json();
    const status = anBody?.data?.attributes?.status;
    if (status === "completed") {
      const stats = anBody?.data?.attributes?.stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      if (malicious > 0 || suspicious > 0) {
        return {
          ok: false,
          status: "malicious",
          malicious,
          suspicious,
          engineCount: Object.values(stats).reduce((a, b) => a + Number(b || 0), 0),
          id: analysisId,
          provider: "virustotal",
          source: "upload",
        };
      }
      return {
        ok: true,
        status: "clean",
        malicious: 0,
        suspicious: 0,
        engineCount: Object.values(stats).reduce((a, b) => a + Number(b || 0), 0),
        id: analysisId,
        provider: "virustotal",
        source: "upload",
      };
    }
  }

  const err = new Error(
    "Scan is taking too long. Please try again with a smaller file, or wait a moment."
  );
  err.code = "VT_TIMEOUT";
  throw err;
}

module.exports = {
  MAX_BYTES,
  ALLOWED,
  sanitizeFilename,
  validateBuffer,
  scanWithVirusTotal,
  getExt,
};
