async function req(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && !url.startsWith('/api/auth/login')) window.dispatchEvent(new Event('auth-expired'));
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export const api = {
  me: () => req('GET', '/api/auth/me'),
  login: (email, password) => req('POST', '/api/auth/login', { email, password }),
  logout: () => req('POST', '/api/auth/logout'),
  changePassword: (currentPassword, newPassword) => req('POST', '/api/auth/change-password', { currentPassword, newPassword }),
  users: () => req('GET', '/api/users'),
  addUser: (u) => req('POST', '/api/users', u),
  updateUser: (id, u) => req('PUT', `/api/users/${id}`, u),
  resetPassword: (id) => req('POST', `/api/users/${id}/reset-password`, {}),
  deleteUser: (id) => req('DELETE', `/api/users/${id}`),
  clients: () => req('GET', '/api/clients'),
  addClient: (c) => req('POST', '/api/clients', c),
  updateClient: (id, c) => req('PUT', `/api/clients/${id}`, c),
  deleteClient: (id) => req('DELETE', `/api/clients/${id}`),
  setPartner: (id, partnerType) => req('PUT', `/api/clients/${id}/partner`, { partnerType }),
  amc: (id) => req('GET', `/api/clients/${id}/amc`),
  logSources: (id) => req('GET', `/api/clients/${id}/logs/sources`),
  fetchLogs: (id, body) => req('POST', `/api/clients/${id}/logs/fetch`, body),
  logJob: (id, job) => req('GET', `/api/clients/${id}/logs/jobs/${job}`),
  cancelLogJob: (id, job) => req('POST', `/api/clients/${id}/logs/jobs/${job}/cancel`, {}),
  scan: (id) => req('POST', `/api/scan/${id}`),
  scanAll: () => req('POST', '/api/scan/all'),
  job: (id) => req('GET', `/api/jobs/${id}`),
  reports: () => req('GET', '/api/reports'),
};
