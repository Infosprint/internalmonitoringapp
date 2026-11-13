async function req(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export const api = {
  clients: () => req('GET', '/api/clients'),
  addClient: (c) => req('POST', '/api/clients', c),
  updateClient: (id, c) => req('PUT', `/api/clients/${id}`, c),
  deleteClient: (id) => req('DELETE', `/api/clients/${id}`),
  scan: (id) => req('POST', `/api/scan/${id}`),
  scanAll: () => req('POST', '/api/scan/all'),
  job: (id) => req('GET', `/api/jobs/${id}`),
  reports: () => req('GET', '/api/reports'),
};
