/**
 * The only outbound network chokepoint. Every request target is an already
 * validated connector URL; no other broker file may call fetch.
 */
export async function netFetch(url: URL, init: RequestInit): Promise<Response> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("upstream protocol must be http or https");
  }
  if (url.username || url.password) {
    throw new Error("upstream URL must not contain credentials");
  }
  return fetch(url, { ...init, redirect: "manual" });
}
