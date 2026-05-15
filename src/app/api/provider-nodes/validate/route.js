import { NextResponse } from "next/server";
import { isIP } from "net";

// Fetch with timeout wrapper
const fetchWithTimeout = (url, options, timeout = 10000) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error("Request timeout")), timeout)
    )
  ]);
};

// Validate URL format
const isValidUrl = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

// Parse error details for user-friendly messages
const getErrorMessage = (error) => {
  if (error.cause?.code === "ECONNREFUSED") return "Connection refused - provider node offline or unreachable";
  if (error.cause?.code === "ENOTFOUND") return "DNS lookup failed - invalid domain or network issue";
  if (error.cause?.code === "ETIMEDOUT") return "Connection timeout - provider node too slow";
  if (error.message.includes("timeout")) return "Request timeout (>10s) - provider node not responding";
  if (error.cause?.code === "CERT_HAS_EXPIRED") return "SSL certificate expired";
  if (error.cause?.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE") return "SSL certificate verification failed";
  if (error.cause?.code) return `Network error: ${error.cause.code}`;
  return "Network connection failed - check URL and network connectivity";
};

// Get status-specific error message for /models endpoint
const getModelsErrorMessage = (status) => {
  if (status === 401 || status === 403) return "API key unauthorized";
  if (status === 404) return "/models endpoint not found - try chat validation with model ID";
  if (status >= 500) return "Server error - try again later";
  return `Unexpected response (${status})`;
};

// Get status-specific error message for /chat/completions endpoint
const getChatErrorMessage = (status) => {
  if (status === 401 || status === 403) return "API key unauthorized";
  if (status === 400) return "Invalid model or bad request";
  if (status === 404) return "Chat endpoint not found";
  if (status >= 500) return "Server error - try again later";
  return `Chat request failed (${status})`;
};

// --- SSRF Protection ---

// Convert IPv4 string to numeric for range comparison
const ipToNum = (ip) => {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
};

// Private/reserved CIDR blocks
const PRIVATE_BLOCKS = [
  { start: ipToNum("10.0.0.0"), end: ipToNum("10.255.255.255") },
  { start: ipToNum("172.16.0.0"), end: ipToNum("172.31.255.255") },
  { start: ipToNum("192.168.0.0"), end: ipToNum("192.168.255.255") },
  { start: ipToNum("127.0.0.0"), end: ipToNum("127.255.255.255") },
  { start: ipToNum("169.254.0.0"), end: ipToNum("169.254.255.255") },
  { start: ipToNum("100.64.0.0"), end: ipToNum("100.127.255.255") },
  { start: ipToNum("0.0.0.0"), end: ipToNum("0.255.255.255") },
  { start: ipToNum("198.18.0.0"), end: ipToNum("198.19.255.255") },
];

const isPrivateIPv4 = (ip) => {
  if (isIP(ip) !== 4) return false;
  const num = ipToNum(ip);
  return PRIVATE_BLOCKS.some(b => num >= b.start && num <= b.end);
};

const isPrivateIPv6 = (ip) => {
  if (isIP(ip) !== 6) return false;
  const lower = ip.toLowerCase();
  // ::1 (loopback), fc00::/7 (unique local), fe80::/10 (link-local)
  if (lower === "::1") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("fe80") || lower.startsWith("fe81") || lower.startsWith("fe82") || lower.startsWith("fe83")) return true;
  if (lower.startsWith("fe84") || lower.startsWith("fe85") || lower.startsWith("fe86") || lower.startsWith("fe87")) return true;
  if (lower.startsWith("fe88") || lower.startsWith("fe89") || lower.startsWith("fe8a") || lower.startsWith("fe8b")) return true;
  if (lower.startsWith("fe8c") || lower.startsWith("fe8d") || lower.startsWith("fe8e") || lower.startsWith("fe8f")) return true;
  if (lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
  return false;
};

const isPrivateHost = (hostname) => {
  // IP literal check
  const ipVersion = isIP(hostname);
  if (ipVersion === 4) return isPrivateIPv4(hostname);
  if (ipVersion === 6) return isPrivateIPv6(hostname);

  // hostname — resolve DNS
  const lower = hostname.toLowerCase();
  // Private-use TLDs / well-known internal domains
  if (lower.endsWith(".local") || lower.endsWith(".internal") || 
      lower.endsWith(".lan") || lower.endsWith(".home.arpa") ||
      lower === "localhost") return true;

  return false; // allow DNS resolution to proceed; fetch will resolve
};

// Validate URL against SSRF — returns error string or null (ok)
const validateUrlForSSRF = (urlStr) => {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    return "Invalid URL format";
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return "Only http/https URLs are allowed";
  }

  const hostname = parsed.hostname;
  if (isPrivateHost(hostname)) {
    return "URL points to a private/internal network address";
  }

  return null; // pass
};

// --- End SSRF Protection ---

// POST /api/provider-nodes/validate - Validate API key against base URL
export async function POST(request) {
  try {
    const body = await request.json();
    const { baseUrl, apiKey, type, modelId } = body;

    if (!baseUrl || !apiKey) {
      return NextResponse.json({ error: "Base URL and API key required" }, { status: 400 });
    }

    // Validate URL format
    if (!isValidUrl(baseUrl)) {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
    }

    // SSRF check — block private/internal network targets
    const ssrfError = validateUrlForSSRF(baseUrl);
    if (ssrfError) {
      return NextResponse.json({ error: ssrfError }, { status: 400 });
    }

    // Custom Embedding Validation - test POST /embeddings directly
    if (type === "custom-embedding") {
      const normalizedBase = baseUrl.trim().replace(/\/$/, "");
      if (!modelId?.trim()) {
        return NextResponse.json({ valid: false, error: "Model ID required for embedding validation" });
      }
      const embedRes = await fetchWithTimeout(`${normalizedBase}/embeddings`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ model: modelId.trim(), input: "ping" })
      });
      if (embedRes.ok) {
        const data = await embedRes.json().catch(() => null);
        const dims = Array.isArray(data?.data?.[0]?.embedding) ? data.data[0].embedding.length : null;
        return NextResponse.json({ valid: true, method: "embeddings", dimensions: dims });
      }
      if (embedRes.status === 401 || embedRes.status === 403) {
        return NextResponse.json({ valid: false, error: "API key unauthorized" });
      }
      const errBody = await embedRes.text().catch(() => "");
      return NextResponse.json({
        valid: false,
        error: `Embeddings request failed (${embedRes.status})${errBody ? `: ${errBody.slice(0, 200)}` : ""}`,
        method: "embeddings"
      });
    }

    // Anthropic Compatible Validation
    if (type === "anthropic-compatible") {
      let normalizedBase = baseUrl.trim().replace(/\/$/, "");
      if (normalizedBase.endsWith("/messages")) {
        normalizedBase = normalizedBase.slice(0, -9);
      }

      const modelsUrl = `${normalizedBase}/models`;
      const res = await fetchWithTimeout(modelsUrl, {
        method: "GET",
        headers: {
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
          "Authorization": `Bearer ${apiKey}`
        }
      });

      if (res.ok) return NextResponse.json({ valid: true });

      // Auth errors - no point trying chat fallback
      if (res.status === 401 || res.status === 403) {
        return NextResponse.json({ valid: false, error: "API key unauthorized" });
      }

      // Fallback: try chat/completions if modelId provided
      if (modelId) {
        const chatRes = await fetchWithTimeout(`${normalizedBase}/chat/completions`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01"
          },
          body: JSON.stringify({
            model: modelId,
            messages: [{ role: "user", content: "ping" }],
            max_tokens: 1
          })
        });
        if (chatRes.ok) {
          return NextResponse.json({ valid: true, method: "chat" });
        }
        return NextResponse.json({
          valid: false,
          error: getChatErrorMessage(chatRes.status),
          method: "chat"
        });
      }

      return NextResponse.json({ valid: false, error: getModelsErrorMessage(res.status) });
    }

    // OpenAI Compatible Validation (Default)
    const modelsUrl = `${baseUrl.replace(/\/$/, "")}/models`;
    const res = await fetchWithTimeout(modelsUrl, {
      headers: { "Authorization": `Bearer ${apiKey}` },
    });

    if (res.ok) return NextResponse.json({ valid: true });

    // Auth errors - no point trying chat fallback
    if (res.status === 401 || res.status === 403) {
      return NextResponse.json({ valid: false, error: "API key unauthorized" });
    }

    // Fallback: try chat/completions if modelId provided
    if (modelId) {
      const chatRes = await fetchWithTimeout(`${baseUrl.replace(/\/$/, "")}/chat/completions`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: modelId,
          messages: [{ role: "user", content: "ping" }],
          max_tokens: 1
        })
      });
      if (chatRes.ok) {
        return NextResponse.json({ valid: true, method: "chat" });
      }
      return NextResponse.json({
        valid: false,
        error: getChatErrorMessage(chatRes.status),
        method: "chat"
      });
    }

    return NextResponse.json({ valid: false, error: getModelsErrorMessage(res.status) });
  } catch (error) {
    const errorMessage = getErrorMessage(error);
    console.error("Error validating provider node:", {
      message: error.message,
      cause: error.cause,
      code: error.cause?.code,
      userMessage: errorMessage
    });
    return NextResponse.json({ 
      valid: false,
      error: errorMessage 
    }, { status: 500 });
  }
}