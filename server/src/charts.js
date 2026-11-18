'use strict';
// Small dependency-free SVG line charts for the AMC section (HTML report and console).
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// series: [{ name, color, values: [number|null...] }]; startMs/stepMs place the x labels (one tick per day)
function lineChart({ series, startMs, stepMs = 3600000, width = 520, height = 170, yMax = 100, unit = '%', title = '' }) {
  const m = { l: 34, r: 10, t: 22, b: 24 };
  const w = width - m.l - m.r; const h = height - m.t - m.b;
  const n = Math.max(...series.map((s) => s.values.length), 1);
  const x = (i) => m.l + (n <= 1 ? 0 : (i / (n - 1)) * w);
  const y = (v) => m.t + h - (Math.min(v, yMax) / yMax) * h;
  let g = '';
  for (const t of [0, 25, 50, 75, 100]) {
    const v = (t / 100) * yMax;
    g += `<line x1="${m.l}" x2="${width - m.r}" y1="${y(v)}" y2="${y(v)}" stroke="#e4e7eb"/><text x="${m.l - 4}" y="${y(v) + 3}" text-anchor="end" font-size="9" fill="#52606d">${Math.round(v)}${unit}</text>`;
  }
  const perDay = Math.round(86400000 / stepMs);
  const everyDays = Math.max(1, Math.ceil(n / perDay / 8));
  for (let i = 0; i < n; i += perDay * everyDays) {
    const d = new Date(startMs + i * stepMs);
    g += `<text x="${x(i)}" y="${height - 8}" font-size="9" fill="#52606d" text-anchor="start">${d.toISOString().slice(5, 10)}</text>`;
  }
  const paths = series.map((s) => {
    let d = ''; let pen = false;
    s.values.forEach((v, i) => { if (v === null || v === undefined) { pen = false; return; } d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`; pen = true; });
    return `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="1.5"${s.dash ? ' stroke-dasharray="3 2"' : ''}/>`;
  }).join('');
  const legend = series.map((s, k) => `<text x="${m.l + 6 + k * 90}" y="12" font-size="10" fill="${s.color}">&#9632; ${esc(s.name)}</text>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" style="max-width:${width}px;background:#fff;border:1px solid #e4e7eb;border-radius:6px" role="img" aria-label="${esc(title)}">${legend}${g}${paths}</svg>`;
}

const cpuChart = (inst, period) => inst.cpu ? lineChart({
  startMs: new Date(period.start).getTime(), title: `CPU utilisation of ${inst.instanceId}`,
  series: [{ name: 'CPU average', color: '#1a73e8', values: inst.cpu.avg }, { name: 'CPU peak', color: '#d93025', values: inst.cpu.max, dash: true }],
}) : '';
const memChart = (inst, period) => inst.memory ? lineChart({
  startMs: new Date(period.start).getTime(), title: `Memory utilisation of ${inst.instanceId}`,
  series: [{ name: 'RAM average', color: '#188038', values: inst.memory.avg }, { name: 'RAM peak', color: '#f29900', values: inst.memory.max, dash: true }],
}) : '';

module.exports = { lineChart, cpuChart, memChart };
