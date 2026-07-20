export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000";

function token() {
  return typeof window !== "undefined" ? localStorage.getItem("accessToken") : null;
}

export async function api(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: {
      "content-type": "application/json",
      ...(token() ? { authorization: `Bearer ${token()}` } : {}),
      ...opts.headers,
    },
  });
  if (res.status === 204) return null;
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const msg = Array.isArray(body.error)
      ? body.error.map((i: any) => i.message).join(", ")
      : body.error || res.statusText;
    throw new Error(msg);
  }
  return res.json();
}
