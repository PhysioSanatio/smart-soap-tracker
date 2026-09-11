// REVOREM Public Intake API v1.0
// Path: /api/revorem-intake.js
//
// Purpose:
// 1) Cloudflare Turnstile server-side verification
// 2) Basic request/payload validation
// 3) Inject server-only REVOREM_PUBLIC_API_SECRET
// 4) Proxy validated pre-intake submissions to Google Apps Script
//
// Required Vercel Environment Variables:
// - TURNSTILE_SECRET_KEY
// - REVOREM_PUBLIC_API_SECRET
// - REVOREM_GAS_URL

const MAX_BODY_BYTES = 256 * 1024; // 256 KB
const ALLOWED_HOSTNAMES = new Set(["revorem.kr"]);

function jsonError(res, status, message) {
  return res.status(status).json({
    result: "error",
    message
  });
}

function gasUrl() {
  const url = String(process.env.REVOREM_GAS_URL || "").trim();
  if (!url) throw new Error("REVOREM_GAS_URL is not configured.");
  return url;
}

function publicSecret() {
  const secret = String(process.env.REVOREM_PUBLIC_API_SECRET || "").trim();
  if (!secret) throw new Error("REVOREM_PUBLIC_API_SECRET is not configured.");
  return secret;
}

function turnstileSecret() {
  const secret = String(process.env.TURNSTILE_SECRET_KEY || "").trim();
  if (!secret) throw new Error("TURNSTILE_SECRET_KEY is not configured.");
  return secret;
}

function normalizeBody(req) {
  if (req.body && typeof req.body === "object") {
    return { ...req.body };
  }

  if (typeof req.body === "string" && req.body.trim()) {
    return JSON.parse(req.body);
  }

  return {};
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").trim();
  if (forwarded) return forwarded.split(",")[0].trim();

  return String(
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    ""
  ).trim();
}

function validateBasicPayload(payload) {
  const name = String(payload.name || "").trim();
  const phone = String(payload.phone || payload.patientPhone || "").trim();
  const age = Number(payload.age);
  const region = String(payload.region || payload.area || "").trim();

  if (!name || name.length > 80) {
    return "성함 정보가 올바르지 않습니다.";
  }

  if (!phone || phone.length > 30) {
    return "연락처 정보가 올바르지 않습니다.";
  }

  if (!Number.isFinite(age) || age < 1 || age > 120) {
    return "나이 정보가 올바르지 않습니다.";
  }

  const allowedRegions = new Set([
    "NDI", "SPADI", "PRTEE", "ODI", "HOOS", "KOOS", "FAAM"
  ]);

  if (!allowedRegions.has(region)) {
    return "평가 부위 정보가 올바르지 않습니다.";
  }

  return null;
}

async function verifyTurnstile(token, remoteip) {
  const form = new URLSearchParams();
  form.set("secret", turnstileSecret());
  form.set("response", token);

  if (remoteip) {
    form.set("remoteip", remoteip);
  }

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: form.toString(),
      cache: "no-store"
    }
  );

  if (!response.ok) {
    throw new Error("Turnstile verification request failed.");
  }

  return response.json();
}

async function forwardToAppsScript(payload) {
  const cleanPayload = { ...payload };

  // Never trust a client-supplied server secret or Turnstile token.
  delete cleanPayload.publicSecret;
  delete cleanPayload.adminSecret;
  delete cleanPayload.turnstileToken;

  // Inject the server-only public intake secret.
  cleanPayload.publicSecret = publicSecret();

  const upstream = await fetch(gasUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(cleanPayload),
    redirect: "follow",
    cache: "no-store"
  });

  const text = await upstream.text();

  if (!upstream.ok) {
    throw new Error(`Apps Script upstream error: ${upstream.status}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Apps Script returned invalid JSON.");
  }

  return parsed;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return jsonError(res, 405, "Method Not Allowed");
  }

  try {
    const contentLength = Number(req.headers["content-length"] || 0);
    if (contentLength && contentLength > MAX_BODY_BYTES) {
      return jsonError(res, 413, "요청 데이터가 너무 큽니다.");
    }

    const body = normalizeBody(req);

    const turnstileToken = String(body.turnstileToken || "").trim();
    if (!turnstileToken) {
      return jsonError(res, 400, "Turnstile 인증 토큰이 없습니다.");
    }

    const validationError = validateBasicPayload(body);
    if (validationError) {
      return jsonError(res, 400, validationError);
    }

    const verification = await verifyTurnstile(
      turnstileToken,
      getClientIp(req)
    );

    if (!verification.success) {
      return jsonError(res, 403, "보안 확인에 실패했습니다. 다시 시도해 주세요.");
    }

    const verifiedHostname = String(verification.hostname || "").toLowerCase();
    if (!ALLOWED_HOSTNAMES.has(verifiedHostname)) {
      return jsonError(res, 403, "허용되지 않은 도메인에서 생성된 인증입니다.");
    }

    const upstreamResult = await forwardToAppsScript(body);

    return res.status(200).json(upstreamResult);
  } catch (error) {
    console.error("REVOREM public intake proxy error:", {
      message: error?.message || "unknown"
    });

    return jsonError(
      res,
      500,
      "사전문진 전송 서버 오류입니다. 잠시 후 다시 시도해 주세요."
    );
  }
}
