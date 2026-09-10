import admin from "firebase-admin";

function getFirebaseAdminApp() {
  if (admin.apps.length) return admin.app();

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not configured.");

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is invalid JSON.");
  }

  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

function allowedAdminEmails() {
  return String(process.env.REVOREM_ADMIN_EMAILS || "")
    .split(",")
    .map(v => v.trim().toLowerCase())
    .filter(Boolean);
}

function allowedAdminUids() {
  return String(process.env.REVOREM_ADMIN_UIDS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);
}

async function verifyRevoremAdmin(req) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ")) {
    const err = new Error("Firebase ID Token이 없습니다.");
    err.statusCode = 401;
    throw err;
  }

  const idToken = header.slice(7).trim();
  if (!idToken) {
    const err = new Error("Firebase ID Token이 비어 있습니다.");
    err.statusCode = 401;
    throw err;
  }

  getFirebaseAdminApp();
  const decoded = await admin.auth().verifyIdToken(idToken, true);

  const email = String(decoded.email || "").trim().toLowerCase();
  const uid = String(decoded.uid || "");
  const emails = allowedAdminEmails();
  const uids = allowedAdminUids();

  // REVOREM Security v1.1 — UID-FIRST
  // UID allowlist가 설정되어 있으면 UID 일치를 필수로 요구한다.
  // UID allowlist가 비어 있을 때만 verified email allowlist를 fallback으로 사용한다.
  let isAllowed = false;

  if (uids.length > 0) {
    isAllowed = uids.includes(uid);
  } else {
    isAllowed =
      emails.length > 0 &&
      decoded.email_verified === true &&
      emails.includes(email);
  }

  if (!isAllowed) {
    const err = new Error("REVOREM 관리자 권한이 없습니다.");
    err.statusCode = 403;
    throw err;
  }

  return { uid, email };
}

function gasUrl() {
  const url = String(process.env.REVOREM_GAS_URL || "").trim();
  if (!url) throw new Error("REVOREM_GAS_URL is not configured.");
  return url;
}

function gasSecret() {
  const secret = String(process.env.REVOREM_ADMIN_API_SECRET || "");
  if (!secret) throw new Error("REVOREM_ADMIN_API_SECRET is not configured.");
  return secret;
}

async function proxyGet(req) {
  const url = new URL(gasUrl());
  const source = new URL(req.url, "https://revorem.local");

  for (const [key, value] of source.searchParams.entries()) {
    // callback/adminSecret은 클라이언트가 지정할 수 없게 차단.
    if (key !== "callback" && key !== "adminSecret") {
      url.searchParams.append(key, value);
    }
  }
  url.searchParams.set("adminSecret", gasSecret());

  const upstream = await fetch(url.toString(), {
    method: "GET",
    redirect: "follow",
    cache: "no-store"
  });

  const text = await upstream.text();
  return { status: upstream.ok ? 200 : 502, text };
}

async function proxyPost(req) {
  const body = (req.body && typeof req.body === "object")
    ? { ...req.body }
    : JSON.parse(req.body || "{}");

  // 클라이언트가 Secret을 주입/덮어쓰지 못하게 서버 값으로 강제.
  delete body.adminSecret;
  body.adminSecret = gasSecret();

  const upstream = await fetch(gasUrl(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    redirect: "follow",
    cache: "no-store"
  });

  const text = await upstream.text();
  return { status: upstream.ok ? 200 : 502, text };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  try {
    await verifyRevoremAdmin(req);

    let result;
    if (req.method === "GET") result = await proxyGet(req);
    else if (req.method === "POST") result = await proxyPost(req);
    else {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).json({ result: "error", message: "Method Not Allowed" });
    }

    // Apps Script의 JSON만 통과시킨다. JSONP는 사용하지 않는다.
    let parsed;
    try {
      parsed = JSON.parse(result.text);
    } catch {
      return res.status(502).json({
        result: "error",
        message: "Apps Script가 올바른 JSON을 반환하지 않았습니다."
      });
    }

    return res.status(result.status).json(parsed);
  } catch (error) {
    console.error("REVOREM admin proxy error:", error);
    const status = Number(error.statusCode) || 500;
    return res.status(status).json({
      result: "error",
      message: status === 500 ? "관리자 API 서버 오류입니다." : error.message
    });
  }
}

