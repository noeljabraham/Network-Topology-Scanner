const svg = document.querySelector('#map');
const list = document.querySelector('#devices');
const summary = document.querySelector('#summary');
const scanButton = document.querySelector('#scan');
const NS = 'http://www.w3.org/2000/svg';

function el(name, attrs = {}) {
  const node = document.createElementNS(NS, name);
  Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
  return node;
}

function draw(data) {
  const devices = data.devices || [];
  const online = devices.filter(d => d.state === 'online');
  summary.textContent = `${online.length} online · ${devices.length} known · ${data.scan.network || 'detecting network'}`;
  scanButton.disabled = Boolean(data.scan.running);
  svg.replaceChildren();
  const gateway = devices.find(d => d.role === 'gateway') || online[0];
  const others = devices.filter(d => !gateway || d.ip !== gateway.ip);
  const positions = new Map();
  if (gateway) positions.set(gateway.ip, [500, 300]);
  others.forEach((device, index) => {
    const angle = (Math.PI * 2 * index / Math.max(others.length, 1)) - Math.PI / 2;
    positions.set(device.ip, [500 + Math.cos(angle) * 330, 300 + Math.sin(angle) * 230]);
  });
  for (const link of data.links || []) {
    const a = positions.get(link.source), b = positions.get(link.target);
    if (a && b) svg.append(el('line', {x1:a[0], y1:a[1], x2:b[0], y2:b[1], class:'link'}));
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
    const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = device.state;
    const name = document.createElement('strong'); name.textContent = device.hostname || device.role;
    const details = document.createElement('small');
    const ports = device.open_ports.length ? ` · ports ${device.open_ports.join(', ')}` : '';
    details.textContent = `${device.ip}${device.mac ? ` · ${device.mac}` : ''}${ports}`;
    item.append(badge, name, details);
    return item;
  }));
}

async function refresh() { draw(await (await fetch('/api/topology')).json()); }
scanButton.addEventListener('click', async () => { scanButton.disabled = true; await fetch('/api/scan', {method:'POST'}); });
const events = new EventSource('/api/events');
events.onmessage = event => { const message = JSON.parse(event.data); if (message.type === 'topology') draw(message.data); else refresh(); };
events.onerror = () => setTimeout(refresh, 2000);
refresh();

