/**
 * Forward a phone, email, or directions tap to the hub.
 * The shared secret stays in QUOTE_API_SECRET. It is never sent to the browser.
 */

const https = require("https");

function json(res, status) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ ok: status === 200 }));
}

function readBody(req) {
  return new Promise((resolve) => {
    if (Buffer.isBuffer(req.body)) {
      try {
        resolve(JSON.parse(req.body.toString("utf8") || "{}"));
      } catch (err) {
        resolve({});
      }
      return;
    }
    if (req.body && typeof req.body === "object") {
      resolve(req.body);
      return;
    }
    if (typeof req.body === "string" && req.body) {
      try {
        resolve(JSON.parse(req.body));
      } catch (err) {
        resolve({});
      }
      return;
    }
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 4000) {
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function postHub(secret, payload) {
  const data = JSON.stringify(payload);
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: "hub.barn-beam.com",
        path: "/api/public/site-taps",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
          "X-Barn-Beam-Secret": secret,
        },
        timeout: 8000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode || 0);
      }
    );
    req.on("error", () => resolve(0));
    req.on("timeout", () => {
      req.destroy();
      resolve(0);
    });
    req.write(data);
    req.end();
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405);
    return;
  }
  const secret = (process.env.QUOTE_API_SECRET || "").trim();
  if (!secret) {
    json(res, 503);
    return;
  }
  const body = await readBody(req);
  const kind = String((body && body.kind) || "").trim().toLowerCase();
  let page = String((body && body.page) || "/").trim();
  if (kind !== "phone" && kind !== "email" && kind !== "directions") {
    json(res, 400);
    return;
  }
  if (!page.startsWith("/") || page.length > 200 || /[?#\s]/.test(page)) {
    page = "/";
  }
  const status = await postHub(secret, { kind: kind, page: page });
  json(res, status === 200 ? 200 : 502);
};
