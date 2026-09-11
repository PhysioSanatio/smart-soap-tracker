import admin from "firebase-admin";

const ALLOWED_GET_ACTIONS = new Set([
  "version",
  "findMember",
  "getMember",
  "memberSummary",
  "crmAnalytics",
  "getLatest"
]);

const ALLOWED_POST_ACTIONS = new Set([
  "confirmActualVisit",
  "ensureMember",
  "recordVisit",
  "upsertEpisode",
  "recordPurchase",
  "recordRegistration",
  "updateMember",
  "saveSession"
]);

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

  if (!url) {
    throw new Error("REVOREM_GAS_URL is not configured.");
  }

  return url;
}

function gasSecret() {
  const secret = String(process.env.REVOREM_ADMIN_API_SECRET || "");

  if (!secret) {
    throw new Error("REVOREM_ADMIN_API_SECRET is not configured.");
  }

  return secret;
}

function getActionFromGet(req) {
  const source = new URL(req.url, "https://revorem.local");
  return String(source.searchParams.get("action") || "").trim();
}

function getPostBody(req) {
  if (req.body && typeof req.body === "object") {
    return { ...req.body };
  }

  return JSON.parse(req.body || "{}");
}

function requireAllowedGetAction(req) {
  const action = getActionFromGet(req);

  if (!action || !ALLOWED_GET_ACTIONS.has(action)) {
    const err = new Error("허용되지 않은 관리자 API action입니다.");
    err.statusCode = 400;
    throw err;
  }

  return action;
}

function requireAllowedPostAction(body) {
  const action = String(body.action || "").trim();

  if (!action || !ALLOWED_POST_ACTIONS.has(action)) {
    const err = new Error("허용되지 않은 관리자 API action입니다.");
    err.statusCode = 400;
    throw err;
  }

  return action;
}

async function proxyGet(req) {
  requireAllowedGetAction(req);

  const url = new URL(gasUrl());
  const source = new URL(req.url, "https://revorem.local");

  for (const [key, value] of source.searchParams.entries()) {
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

  return {
    status: upstream.ok ? 200 : 502,
    text
  };
}

async function proxyPost(req) {
  const body = getPostBody(req);

  requireAllowedPostAction(body);

  delete body.adminSecret;
  body.adminSecret = gasSecret();

  const upstream = await fetch(gasUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body),
    redirect: "follow",
    cache: "no-store"
  });

  const text = await upstream.text();

  return {
    status: upstream.ok ? 200 : 502,
    text
  };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");

  try {
    await verifyRevoremAdmin(req);

    let result;

    if (req.method === "GET") {
      result = await proxyGet(req);
    } else if (req.method === "POST") {
      result = await proxyPost(req);
    } else {
      res.setHeader("Allow", "GET, POST");

      return res.status(405).json({
        result: "error",
        message: "Method Not Allowed"
      });
    }

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
    console.error("REVOREM admin proxy error:", {
      message: error?.message || "unknown",
      name: error?.name || ""
    });

    const status = Number(error.statusCode) || 500;

    return res.status(status).json({
      result: "error",
      message:
        status === 500
          ? "관리자 API 서버 오류입니다."
          : error.message
    });
  }
}
