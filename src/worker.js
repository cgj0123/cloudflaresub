// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

// Cloudflare Worker: KV short link subscription + access token protection
// Supports: vmess, vless, trojan, hysteria2, shadowsocks

// Cloudflare Worker: 优选IP订阅生成器（支持自动提取 IP）
// Supports: vmess, vless, trojan, hysteria2, shadowsocks

// Cloudflare Worker: 优选IP订阅生成器（自动解析 DNS + 强制保留 SNI）
// 支持 vmess, vless, trojan, hysteria2, shadowsocks

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,OPTIONS' },
  });
}
function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, { status, headers: { 'content-type': contentType, 'access-control-allow-origin': '*' } });
}
function b64EncodeUtf8(str) { return btoa(unescape(encodeURIComponent(str))); }
function b64DecodeUtf8(str) { return decodeURIComponent(escape(atob(str))); }
function escapeYaml(s) { return JSON.stringify(String(s)); }

// ---------- DNS 解析 ----------
async function resolveDomainToIPs(domain) {
  if (!domain) return [];
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`;
    const resp = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    if (data.Answer) return data.Answer.filter(r => r.type === 1).map(r => r.data);
  } catch (e) { console.error(e); }
  return [];
}

function parsePreferredEndpoints(input) {
  return String(input || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(line => {
    const [raw, remark = ''] = line.split('#');
    const match = raw.trim().match(/^(.*?)(?::(\d+))?$/);
    return { server: match?.[1] || raw, port: match?.[2] ? Number(match[2]) : undefined, remark: remark.trim() };
  });
}

// ---------- 节点解析器 ----------
function parseVmess(link) {
  const obj = JSON.parse(b64DecodeUtf8(link.slice(8)));
  return { type: 'vmess', name: obj.ps || 'vmess', server: obj.add, port: Number(obj.port || 443), uuid: obj.id, cipher: obj.scy || 'auto', network: obj.net || 'ws', tls: obj.tls === 'tls', host: obj.host || '', path: obj.path || '/', sni: obj.sni || obj.host || '', alpn: obj.alpn || '', fp: obj.fp || '', originalServer: obj.add };
}
function parseUrlLike(link, type) {
  const u = new URL(link);
  const base = { type, name: decodeURIComponent(u.hash.slice(1)) || type, server: u.hostname, port: Number(u.port || 443), network: u.searchParams.get('type') || 'tcp', tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls', host: u.searchParams.get('host') || '', path: u.searchParams.get('path') || '/', sni: u.searchParams.get('sni') || '', alpn: u.searchParams.get('alpn') || '', fp: u.searchParams.get('fp') || '', originalServer: u.hostname };
  if (type === 'trojan') base.password = decodeURIComponent(u.username);
  if (type === 'vless') base.uuid = decodeURIComponent(u.username);
  return base;
}
function parseHysteria2(link) {
  const u = new URL(link);
  let auth = '';
  if (u.username) auth = u.password ? `${u.username}:${u.password}` : u.username;
  return { type: 'hysteria2', name: decodeURIComponent(u.hash.slice(1)) || 'hysteria2', server: u.hostname, port: Number(u.port || 443), auth, sni: u.searchParams.get('sni') || '', insecure: u.searchParams.get('insecure') === '1', alpn: u.searchParams.get('alpn') || '', path: u.searchParams.get('path') || '', obfs: u.searchParams.get('obfs') || '', tls: true, network: 'udp', originalServer: u.hostname };
}
function parseShadowsocks(link) {
  let content = link.slice(5).trim(), name = '';
  const hash = content.indexOf('#');
  if (hash !== -1) { name = decodeURIComponent(content.slice(hash + 1)); content = content.slice(0, hash); }
  let method, password, server, port;
  if (content.includes('@')) {
    const [auth, hp] = content.split('@');
    [method, password] = auth.split(':');
    [server, port] = hp.split(':');
    port = parseInt(port) || 443;
  } else {
    const decoded = b64DecodeUtf8(content);
    const [auth, hp] = decoded.split('@');
    [method, password] = auth.split(':');
    [server, port] = hp.split(':');
    port = parseInt(port) || 443;
  }
  return { type: 'ss', name: name || 'ss', server, port, method, password, plugin: '', originalServer: server };
}
function parseRawLinks(input) {
  const lines = String(input || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) result.push(parseVmess(line));
    else if (line.startsWith('vless://')) result.push(parseUrlLike(line, 'vless'));
    else if (line.startsWith('trojan://')) result.push(parseUrlLike(line, 'trojan'));
    else if (line.startsWith('hysteria2://')) result.push(parseHysteria2(line));
    else if (line.startsWith('ss://')) result.push(parseShadowsocks(line));
    else {
      try { const decoded = b64DecodeUtf8(line); if (/^(vmess|vless|trojan|hysteria2|ss):\/\//.test(decoded)) result.push(...parseRawLinks(decoded)); } catch {}
    }
  }
  return result;
}

// ---------- 节点重建（强制保留 SNI） ----------
function buildNodes(baseNodes, endpoints, opts) {
  const keepHost = opts.keepOriginalHost !== false;
  const prefix = (opts.namePrefix || '').trim();
  const output = [];
  let idx = 0;
  for (const node of baseNodes) {
    for (const ep of endpoints) {
      idx++;
      const nameParts = [node.name];
      if (prefix) nameParts.push(prefix);
      nameParts.push(ep.remark || String(idx));
      const newNode = { ...node, name: nameParts.join(' | '), server: ep.server, port: ep.port || node.port };
      if (keepHost) {
        if (node.type === 'vmess' || node.type === 'vless' || node.type === 'trojan') {
          newNode.host = node.host || '';
          newNode.sni = node.sni || node.originalServer || '';
        }
        if (node.type === 'hysteria2') newNode.sni = node.sni || node.originalServer || '';
      }
      output.push(newNode);
    }
  }
  return output;
}

// ---------- 编码器 ----------
function encodeVmess(n) {
  const obj = { v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.uuid, aid: '0', scy: n.cipher || 'auto', net: n.network || 'ws', type: 'none', host: n.host || '', path: n.path || '/', tls: n.tls ? 'tls' : '', sni: n.sni || '', alpn: n.alpn || '', fp: n.fp || '' };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}
function encodeVless(n) {
  const u = new URL(`vless://${encodeURIComponent(n.uuid)}@${n.server}:${n.port}`);
  u.searchParams.set('type', n.network || 'ws');
  if (n.tls) u.searchParams.set('security', 'tls');
  if (n.host) u.searchParams.set('host', n.host);
  if (n.sni) u.searchParams.set('sni', n.sni);
  if (n.path) u.searchParams.set('path', n.path);
  if (n.alpn) u.searchParams.set('alpn', n.alpn);
  u.hash = n.name;
  return u.toString();
}
function encodeTrojan(n) {
  const u = new URL(`trojan://${encodeURIComponent(n.password)}@${n.server}:${n.port}`);
  if (n.network) u.searchParams.set('type', n.network);
  if (n.tls) u.searchParams.set('security', 'tls');
  if (n.host) u.searchParams.set('host', n.host);
  if (n.sni) u.searchParams.set('sni', n.sni);
  if (n.path) u.searchParams.set('path', n.path);
  u.hash = n.name;
  return u.toString();
}
function encodeHysteria2(n) {
  let authPart = n.auth ? `${n.auth}@` : '';
  const u = new URL(`hysteria2://${authPart}${n.server}:${n.port}`);
  if (n.sni) u.searchParams.set('sni', n.sni);
  if (n.insecure) u.searchParams.set('insecure', '1');
  if (n.alpn) u.searchParams.set('alpn', n.alpn);
  if (n.path) u.searchParams.set('path', n.path);
  u.hash = n.name;
  return u.toString();
}
function encodeShadowsocks(n) {
  const auth = `${n.method}:${n.password}`;
  return `ss://${b64EncodeUtf8(auth)}@${n.server}:${n.port}#${encodeURIComponent(n.name)}`;
}

// ---------- 订阅渲染 ----------
function renderRaw(nodes) {
  const lines = nodes.map(n => {
    if (n.type === 'vmess') return encodeVmess(n);
    if (n.type === 'vless') return encodeVless(n);
    if (n.type === 'trojan') return encodeTrojan(n);
    if (n.type === 'hysteria2') return encodeHysteria2(n);
    if (n.type === 'ss') return encodeShadowsocks(n);
    return '';
  }).filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}
function renderClash(nodes) {
  const lines = [];
  for (const n of nodes) {
    const base = [`  - name: ${escapeYaml(n.name)}`, `    type: ${n.type}`, `    server: ${n.server}`, `    port: ${n.port}`, `    udp: true`];
    if (n.type === 'vmess') base.push(`    uuid: ${n.uuid}`, `    alterId: 0`, `    cipher: ${n.cipher || 'auto'}`);
    if (n.type === 'vless') base.push(`    uuid: ${n.uuid}`);
    if (n.type === 'trojan') base.push(`    password: ${escapeYaml(n.password)}`);
    if (n.type === 'hysteria2') base.push(`    password: ${escapeYaml(n.auth || '')}`, `    tls: true`);
    if (n.type === 'ss') base.push(`    cipher: ${n.method}`, `    password: ${escapeYaml(n.password)}`);
    if (['vmess', 'vless', 'trojan'].includes(n.type)) {
      if (n.tls) base.push(`    tls: true`);
      if (n.sni) base.push(`    servername: ${escapeYaml(n.sni)}`);
      if (n.network === 'ws') base.push(`    network: ws`, `    ws-opts:`, `      path: ${escapeYaml(n.path || '/')}`, `      headers:`, `        Host: ${escapeYaml(n.host || n.sni || '')}`);
    }
    if (n.type === 'hysteria2') {
      if (n.sni) base.push(`    sni: ${escapeYaml(n.sni)}`);
      if (n.insecure) base.push(`    skip-cert-verify: true`);
    }
    lines.push(base.join('\n'));
  }
  const proxyNames = nodes.map(n => `      - ${escapeYaml(n.name)}`);
  return [
    `mixed-port: 7890`, `allow-lan: false`, `mode: rule`, `log-level: info`,
    `proxies:`, ...lines,
    `proxy-groups:`,
    `  - name: "自动选择"`, `    type: url-test`, `    url: "http://www.gstatic.com/generate_204"`, `    interval: 300`, `    tolerance: 50`, `    proxies:`, ...(proxyNames.length ? proxyNames : [`      - DIRECT`]),
    `  - name: "节点选择"`, `    type: select`, `    proxies:`, `      - "自动选择"`, ...proxyNames, `      - DIRECT`,
    `rules:`, `  - MATCH,节点选择`,
  ].join('\n');
}
function renderSurge(nodes, baseUrl, token) {
  const proxies = nodes.filter(n => ['vmess', 'trojan', 'hysteria2', 'ss'].includes(n.type)).map(n => {
    const name = n.name.replace(/[ ,]/g, '_');
    if (n.type === 'vmess') return `${name} = vmess, ${n.server}, ${n.port}, username=${n.uuid}, ws=true, ws-path=${n.path || '/'}, ws-headers=Host:${n.host || ''}, tls=${n.tls}, sni=${n.sni || ''}`;
    if (n.type === 'trojan') return `${name} = trojan, ${n.server}, ${n.port}, password=${n.password}, sni=${n.sni || ''}`;
    if (n.type === 'hysteria2') return `${name} = hysteria2, ${n.server}, ${n.port}, password=${n.auth || ''}, sni=${n.sni || ''}, skip-cert-verify=${n.insecure}`;
    if (n.type === 'ss') return `${name} = shadowsocks, ${n.server}, ${n.port}, encrypt-method=${n.method}, password=${n.password}`;
    return '';
  }).filter(Boolean);
  return [
    '[General]', 'skip-proxy = 127.0.0.1, localhost', '',
    '[Proxy]', ...proxies, '',
    '[Proxy Group]', `Proxy = select, ${proxies.map(p => p.split('=')[0].trim()).join(', ')}`, '',
    '[Rule]', 'FINAL,Proxy',
    `; ${baseUrl}?token=${token}`,
  ].join('\n');
}

// ---------- KV 辅助 ----------
function createShortId(len = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let id = '';
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  for (let i = 0; i < len; i++) id += chars[bytes[i] % chars.length];
  return id;
}
async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    if (!(await env.SUB_STORE.get(`sub:${id}`))) return id;
  }
  throw new Error('无法生成短链接');
}
function normalizeLines(v) { return String(v).split(/\r?\n/).map(l => l.trim()).filter(Boolean).sort().join('\n'); }
async function sha256Hex(s) { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function buildDedupHash(body) {
  return sha256Hex(JSON.stringify({
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: (body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  }));
}

// ---------- 核心 API ----------
async function handleGenerate(request, env, url) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: 'JSON 无效' }, 400); }
  try {
    let baseNodes = parseRawLinks(body.nodeLinks || '');
    if (!baseNodes.length) throw new Error('没有识别到可用节点');

    let preferredIpsText = (body.preferredIps || '').trim();
    let endpoints = parsePreferredEndpoints(preferredIpsText);
    let autoResolved = false;

    // 自动解析域名 IP
    if (endpoints.length === 0 && baseNodes.length > 0) {
      const firstNode = baseNodes[0];
      const domain = firstNode.originalServer || firstNode.server;
      if (domain) {
        const ips = await resolveDomainToIPs(domain);
        if (ips.length) {
          endpoints = ips.map(ip => ({ server: ip, port: undefined, remark: 'auto' }));
          autoResolved = true;
        } else {
          endpoints = [{ server: domain, port: undefined, remark: 'origin' }];
        }
      }
    }
    if (endpoints.length === 0) throw new Error('没有可用优选地址');

    const options = { namePrefix: body.namePrefix || '', keepOriginalHost: body.keepOriginalHost !== false };
    const nodes = buildNodes(baseNodes, endpoints, options);
    if (!nodes.length) throw new Error('节点组合为空');

    const payload = { version: 1, createdAt: new Date().toISOString(), nodes };
    const hash = await buildDedupHash(body);
    let id = await env.SUB_STORE.get(`dedup:${hash}`);
    if (!id) {
      id = await createUniqueShortId(env);
      await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), { expirationTtl: 604800 });
      await env.SUB_STORE.put(`dedup:${hash}`, id, { expirationTtl: 604800 });
    }

    const token = env.SUB_ACCESS_TOKEN || '';
    const base = `${url.origin}/sub/${id}`;
    const t = (target) => `${base}${target ? `?target=${target}` : ''}${token ? `&token=${encodeURIComponent(token)}` : ''}`.replace('?&', '?');

    const warnings = [];
    if (!token) warnings.push('未设置 SUB_ACCESS_TOKEN，订阅链接无保护');
    if (autoResolved) warnings.push(`未提供优选 IP，已自动从节点域名解析出 ${endpoints.length} 个 IP，如仍无法使用请手动填写正确 CDN IP。`);

    return json({
      ok: true, shortId: id,
      urls: { auto: t(''), raw: t('raw'), clash: t('clash'), surge: t('surge') },
      counts: { inputNodes: baseNodes.length, preferredEndpoints: endpoints.length, outputNodes: nodes.length },
      preview: nodes.slice(0, 20).map(n => ({ name: n.name, type: n.type, server: n.server, port: n.port, host: n.host || '', sni: n.sni || '' })),
      warnings,
    });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: err.message }, 400);
  }
}

function validateToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return true;
  const provided = url.searchParams.get('token') || '';
  return provided === expected;
}
async function handleSub(url, env) {
  if (!validateToken(url, env)) return text('Forbidden', 403);
  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);
  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);
  const { nodes } = JSON.parse(raw);
  const target = url.searchParams.get('target') || 'raw';
  if (target === 'clash') return text(renderClash(nodes), 200, 'text/yaml');
  if (target === 'surge') return text(renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''), 200, 'text/plain');
  return text(renderRaw(nodes), 200);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,OPTIONS' } });
    if (request.method === 'POST' && url.pathname === '/api/generate') return handleGenerate(request, env, url);
    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) return handleSub(url, env);
    return env.ASSETS.fetch(request);
  },
};
