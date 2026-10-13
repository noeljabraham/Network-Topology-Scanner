const svg = document.querySelector('#map');
const list = document.querySelector('#devices');
const summary = document.querySelector('#summary');
const scanButton = document.querySelector('#scan');
const profile = document.querySelector('#profile');
const NS = 'http://www.w3.org/2000/svg';
const token = new URLSearchParams(location.search).get('token') || localStorage.getItem('networkMapToken') || '';
if (token) localStorage.setItem('networkMapToken', token);
if (token) document.querySelector('.export').href = `/api/export.csv?token=${encodeURIComponent(token)}`;

function headers(extra = {}) { return token ? {...extra, Authorization:`Bearer ${token}`} : extra; }
async function api(url, options = {}) {
  const response = await fetch(url, {...options, headers:headers(options.headers || {})});
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || response.statusText);
  return response.json();
}
function el(name, attrs = {}) {
  const node = document.createElementNS(NS, name);
  Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
  return node;
}
function textElement(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  return node;
}

function draw(data) {
  const devices = data.devices || [], online = devices.filter(d => d.state === 'online');
  const status = data.scan.running ? ` · ${data.scan.profile} scan running` : data.scan.last_error ? ` · error: ${data.scan.last_error}` : '';
  summary.textContent = `${online.length} online · ${devices.length} known · ${data.scan.network || 'detecting network'}${status}`;
  scanButton.disabled = Boolean(data.scan.running);
  svg.replaceChildren();
  const gateway = devices.find(d => d.role === 'gateway') || online[0];
  const others = devices.filter(d => !gateway || d.ip !== gateway.ip), positions = new Map();
  if (gateway) positions.set(gateway.ip, [500, 300]);
  others.forEach((device, index) => {
    const angle = (Math.PI * 2 * index / Math.max(others.length, 1)) - Math.PI / 2;
    positions.set(device.ip, [500 + Math.cos(angle) * 330, 300 + Math.sin(angle) * 230]);
  });
  for (const link of data.links || []) {
    const a = positions.get(link.source), b = positions.get(link.target);
    if (a && b) {
      const line = el('line', {x1:a[0], y1:a[1], x2:b[0], y2:b[1], class:'link'});
      if (link.kind === 'observed') line.style.strokeDasharray = 'none';
      const title = el('title');
      title.textContent = `${link.kind}: ${link.evidence || ''} (${Math.round(link.confidence * 100)}%)`;
      line.append(title); svg.append(line);
    }
  }
  for (const device of devices) {
    const [x, y] = positions.get(device.ip) || [500, 300];
    const group = el('g', {class:`node ${device.state} ${device.role}`, transform:`translate(${x} ${y})`});
    group.append(el('circle', {r:device.role === 'gateway' ? 34 : 27}));
    const title = el('text', {y:50}); title.textContent = device.hostname || device.role;
    const sub = el('text', {y:67, class:'sub'}); sub.textContent = device.ip;
    group.append(title, sub); svg.append(group);
  }
  list.replaceChildren(...devices.map(device => {
    const item = document.createElement('div'); item.className = 'device';
    item.append(textElement('span', device.state, 'badge'), textElement('strong', device.hostname || device.role));
    item.append(textElement('small', [device.ip, device.mac, device.vendor].filter(Boolean).join(' · ')));
    if (device.os_name) item.append(textElement('small', `OS: ${device.os_name}${device.os_accuracy ? ` (${device.os_accuracy}%)` : ''}`));
    const services = (device.services || []).filter(s => s.state === 'open').map(s => `${s.port}/${s.protocol} ${s.product || s.name || ''}`.trim());
    if (services.length) item.append(textElement('small', `Services: ${services.join(', ')}`));
    for (const source of device.sources || []) item.append(textElement('span', source, 'source'));
    return item;
  }));
}

async function refresh() {
  try { draw(await api('/api/topology')); }
  catch (error) { summary.textContent = error.message; }
}
scanButton.addEventListener('click', async () => {
  scanButton.disabled = true;
  try {
    await api('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({profile:profile.value, engine:'nmap'})});
    await refresh();
  } catch (error) { summary.textContent = error.message; scanButton.disabled = false; }
});
const events = new EventSource(`/api/events${token ? `?token=${encodeURIComponent(token)}` : ''}`);
events.onmessage = event => {
  const message = JSON.parse(event.data);
  if (message.type === 'topology') draw(message.data); else refresh();
};
events.onerror = () => setTimeout(refresh, 2000);
refresh();
