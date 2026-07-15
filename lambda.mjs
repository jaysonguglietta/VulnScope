import { handleApiRequest } from "./server.mjs";

export async function handler(event) {
  try {
    const path = event.rawPath || event.requestContext?.http?.path || "/";
    const query = new URLSearchParams(event.rawQueryString || "");
    const response = await handleApiRequest({
      path,
      method: event.requestContext?.http?.method || "GET",
      query,
      headers: normalizeHeaders(event.headers || {}),
      remoteAddress: event.requestContext?.http?.sourceIp || "unknown",
      trustedClientAddress: event.requestContext?.http?.sourceIp || "unknown",
      body: decodeBody(event)
    });

    if (response) {
      return {
        ...response,
        isBase64Encoded: false
      };
    }

    return {
      statusCode: 404,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      },
      body: JSON.stringify({ error: true, message: "Not found." }),
      isBase64Encoded: false
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      },
      body: JSON.stringify({
        error: true,
        message: "The research server hit an unexpected error."
      }),
      isBase64Encoded: false
    };
  }
}

function decodeBody(event) {
  if (!event.body) return "";
  return event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : String(event.body);
}

function normalizeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}
