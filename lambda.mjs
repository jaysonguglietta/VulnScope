import { handleApiRequest } from "./server.mjs";

export async function handler(event) {
  try {
    const path = event.rawPath || event.requestContext?.http?.path || "/";
    const query = new URLSearchParams(event.rawQueryString || "");
    const response = await handleApiRequest({
      path,
      query,
      headers: normalizeHeaders(event.headers || {}),
      remoteAddress: event.requestContext?.http?.sourceIp || "unknown"
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

function normalizeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}
