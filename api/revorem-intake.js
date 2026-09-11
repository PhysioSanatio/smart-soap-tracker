// REVOREM Public Intake API v1.1
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

/*
 * Cloudflare 공식 Siteverify API를 JSON 방식으로 호출합니다.
 * remoteip은 선택값이므로 일단 제외해 네트워크/프록시 IP 형식 변수를 제거합니다.
 * 실패 시 Secret/Token 자체는 로그에 남기지 않고 HTTP status와 error-codes만 기록합니다.
 */
async function verifyTurnstile(token) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          secret: turnstileSecret(),
          response: token
        }),
        cache: "no-store",
        signal: controller.signal
      }
    );

    const raw = await response.text();

    let result;
    try {
      result = JSON.parse(raw);
    } catch {
      console.error("REVOREM Turnstile invalid JSON response:", {
        status: response.status,
        statusText: response.statusText,
        bodyPreview: raw.slice(0, 300)
      });
      throw new Error(`TURNSTILE_BAD_RESPONSE_${response.status}`);
    }

    if (!response.ok) {
      console.error("REVOREM Turnstile HTTP error:", {
        status: response.status,
        statusText: response.statusText,
        errorCodes: result?.["error-codes"] || []
      });
      throw new Error(`TURNSTILE_HTTP_${response.status}`);
    }

    if (!result.success) {
      console.warn("REVOREM Turnstile verification rejected:", {
        errorCodes: result?.["error-codes"] || [],
        hostname: result?.hostname || "",
        action: result?.action || ""
      });
    }

    return result;
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("TURNSTILE_TIMEOUT");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
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
    console.error("REVOREM Apps Script HTTP error:", {
      status: upstream.status,
      statusText: upstream.statusText,
      bodyPreview: text.slice(0, 300)
    });
    throw new Error(`APPS_SCRIPT_HTTP_${upstream.status}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    console.error("REVOREM Apps Script invalid JSON:", {
      bodyPreview: text.slice(0, 300)
    });
    throw new Error("APPS_SCRIPT_INVALID_JSON");
  }

  if (parsed?.result !== "success") {
    console.error("REVOREM Apps Script application error:", {
      result: parsed?.result || "",
      message: parsed?.message || ""
    });
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

    if (turnstileToken.length > 2048) {
      return jsonError(res, 400, "Turnstile 인증 토큰이 올바르지 않습니다.");
    }

    const validationError = validateBasicPayload(body);
    if (validationError) {
      return jsonError(res, 400, validationError);
    }

    const verification = await verifyTurnstile(turnstileToken);

    if (!verification.success) {
      return jsonError(
        res,
        403,
        "보안 확인에 실패했습니다. 보안 확인을 다시 완료한 뒤 제출해 주세요."
      );
    }

    const verifiedHostname = String(verification.hostname || "")
      .trim()
      .toLowerCase();

    if (!ALLOWED_HOSTNAMES.has(verifiedHostname)) {
      console.warn("REVOREM Turnstile hostname rejected:", {
        hostname: verifiedHostname
      });

      return jsonError(
        res,
        403,
        "허용되지 않은 도메인에서 생성된 보안 인증입니다."
      );
    }

    const upstreamResult = await forwardToAppsScript(body);

    if (!upstreamResult || upstreamResult.result !== "success") {
      return jsonError(
        res,
        502,
        upstreamResult?.message || "사전문진 저장 단계에서 오류가 발생했습니다."
      );
    }

    return res.status(200).json(upstreamResult);
  } catch (error) {
    console.error("REVOREM public intake proxy error:", {
      message: error?.message || "unknown",
      name: error?.name || ""
    });

    return jsonError(
      res,
      500,
      "사전문진 전송 서버 오류입니다. 잠시 후 다시 시도해 주세요."
    );
  }
}
