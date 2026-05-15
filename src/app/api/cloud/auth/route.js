import { NextResponse } from "next/server";
import { validateApiKey, getProviderConnections, getModelAliases } from "@/models";

// Verify API key and return provider configurations (without credentials)
export async function POST(request) {
  try {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return NextResponse.json({ error: "Missing API key" }, { status: 401 });
    }

    const apiKey = authHeader.slice(7);

    // Validate API key
    const isValid = await validateApiKey(apiKey);
    if (!isValid) {
      return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
    }

    // Get active provider connections
    const connections = await getProviderConnections({ isActive: true });

    // Map connections — strip credentials (apiKey, accessToken, refreshToken)
    // to avoid leaking provider secrets to API-key authenticated clients.
    // The proxy injects credentials server-side; clients never need them directly.
    const mappedConnections = connections.map(conn => ({
      provider: conn.provider,
      authType: conn.authType,
      projectId: conn.projectId || null,
      expiresAt: conn.expiresAt,
      priority: conn.priority,
      globalPriority: conn.globalPriority,
      defaultModel: conn.defaultModel,
      isActive: conn.isActive
    }));

    // Get model aliases
    const modelAliases = await getModelAliases();

    return NextResponse.json({
      connections: mappedConnections,
      modelAliases
    });

  } catch (error) {
    console.log("Cloud auth error:", error);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
