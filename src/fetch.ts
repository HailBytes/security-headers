export async function fetchHeaders(url: string): Promise<Record<string, string>> {
  const res = await fetch(url, { method: 'HEAD', redirect: 'follow' });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
  return headers;
}
