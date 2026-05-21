// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

// Cloudflare Worker: KV short link subscription + access token protection
// Supports: vmess, vless, trojan, hysteria2, shadowsocks

// ========== 辅助函数 ==========
function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, ' ');
}

// ========== 优选 IP 解析 ==========
function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

// ========== 节点解析器 ==========
function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseHysteria2(link) {
  const u = new URL(link);
  const params = u.searchParams;
  let auth = '';
  if (u.username) {
    auth = u.password ? `${u.username}:${u.password}` : u.username;
  }
  return {
    type: 'hysteria2',
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || 'hysteria2',
    server: u.hostname,
    port: Number(u.port || 443),
    auth: auth,
    sni: params.get('sni') || '',
    insecure: params.get('insecure') === '1' || params.get('insecure') === 'true',
    alpn: params.get('alpn') || '',
    path: params.get('path') || '',
    obfs: params.get('obfs') || '',
    tls: true,
    network: 'udp',
  };
}

function parseShadowsocks(link) {
  let content = link.slice('ss://'.length).trim();
  let name = '';
  const hashIndex = content.indexOf('#');
  if (hashIndex !== -1) {
    name = decodeURIComponent(content.slice(hashIndex + 1));
    content = content.slice(0, hashIndex);
  }
  let method, password, server, port;
  if (content.includes('@')) {
    const [auth, hostport] = content.split('@');
    [method, password] = auth.split(':');
    const [host, p] = hostport.split(':');
    server = host;
    port = parseInt(p) || 443;
  } else {
    try {
      const decoded = b64DecodeUtf8(content);
      if (decoded.includes('@')) {
        const [auth, hostport] = decoded.split('@');
        [method, password] = auth.split(':');
        const [host, p] = hostport.split(':');
        server = host;
        port = parseInt(p) || 443;
      } else {
        throw new Error('Invalid SS format');
      }
    } catch (e) {
      throw new Error(`Shadowsocks 解析失败: ${link}`);
    }
  }
  return {
    type: 'ss',
    name: name || 'ss',
    server,
    port,
    method,
    password,
    plugin: '',
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) result.push(parseVmess(line));
    else if (line.startsWith('vless://')) result.push(parseUrlLike(line, 'vless'));
    else if (line.startsWith('trojan://')) result.push(parseUrlLike(line, 'trojan'));
    else if (line.startsWith('hysteria2://')) result.push(parseHysteria2(line));
    else if (line.startsWith('ss://')) result.push(parseShadowsocks(line));
    else {
      try {
        const decoded = b64DecodeUtf8(line);
        if (/^(vmess|vless|trojan|hysteria2|ss):\/\//m.test(decoded)) {
          result.push(...parseRawLinks(decoded));
        }
      } catch {}
    }
  }
  return result;
}

// ========== 节点重建 ==========
function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter++;
      const nameParts = [node.name];
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      const newNode = {
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
      };
      // 仅对需要 Host/SNI 的协议进行保留/替换操作
      if (options.keepOriginalHost) {
        if (node.type === 'vmess' || node.type === 'vless' || node.type === 'trojan') {
          newNode.host = node.host || '';
          newNode.sni = node.sni || '';
        }
        // hysteria2 和 ss 不需要 host/sni
      } else {
        if (node.type === 'vmess' || node.type === 'vless' || node.type === 'trojan') {
          if (!node.host || node.host === node.server) newNode.host = ep.server;
          if (!node.sni || node.sni === node.server) newNode.sni = ep.server;
        }
      }
      output.push(newNode);
    }
  }
  return output;
}

// ========== 节点编码器（生成链接） ==========
function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function encodeHysteria2(node) {
  let authPart = '';
  if (node.auth && node.auth.includes(':')) {
    authPart = `${node.auth}@`;
  } else if (node.auth && !node.auth.includes(':')) {
    authPart = `${node.auth}@`;
  }
  const url = new URL(`hysteria2://${authPart}${node.server}:${node.port}`);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.insecure) url.searchParams.set('insecure', '1');
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.obfs) url.searchParams.set('obfs', node.obfs);
  url.hash = node.name;
  return url.toString();
}

function encodeShadowsocks(node) {
  const auth = `${node.method}:${node.password}`;
  const base64Auth = b64EncodeUtf8(auth);
  return `ss://${base64Auth}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
}

// ========== 订阅渲染 ==========
function renderRaw(nodes) {
  const lines = nodes.map(node => {
    if (node.type === 'vmess') return encodeVmess(node);
    if (node.type === 'vless') return encodeVless(node);
    if (node.type === 'trojan') return encodeTrojan(node);
    if (node.type === 'hysteria2') return encodeHysteria2(node);
    if (node.type === 'ss') return encodeShadowsocks(node);
    return '';
  }).filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes.map(node => {
    if (node.type === 'vmess') {
      return [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: vmess`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    uuid: ${node.uuid}`,
        `    alterId: 0`,
        `    cipher: ${node.cipher || 'auto'}`,
        `    udp: true`,
        `    tls: ${node.tls ? 'true' : 'false'}`,
        `    network: ${node.network || 'ws'}`,
        ...(node.sni ? [`    servername: "${escapeYaml(node.sni)}"`] : []),
        ...((node.network || 'ws') === 'ws' ? [
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || '/')}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || '')}"`
        ] : [])
      ].join('\n');
    }
    if (node.type === 'vless') {
      return [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: vless`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    uuid: ${node.uuid}`,
        `    udp: true`,
        `    tls: ${node.tls ? 'true' : 'false'}`,
        `    network: ${node.network || 'ws'}`,
        ...(node.sni ? [`    servername: "${escapeYaml(node.sni)}"`] : []),
        ...((node.network || 'ws') === 'ws' ? [
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || '/')}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || '')}"`
        ] : [])
      ].join('\n');
    }
    if (node.type === 'trojan') {
      return [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: trojan`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    password: "${escapeYaml(node.password || '')}"`,
        `    udp: true`,
        ...(node.sni ? [`    sni: "${escapeYaml(node.sni)}"`] : []),
        `    tls: true`,
        ...(node.network ? [`    network: ${node.network}`] : []),
        ...(node.network === 'ws' ? [
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || '/')}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || '')}"`
        ] : [])
      ].join('\n');
    }
    if (node.type === 'hysteria2') {
      return [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: hysteria2`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    password: "${escapeYaml(node.auth || '')}"`,
        `    udp: true`,
        `    tls: true`,
        ...(node.sni ? [`    sni: "${escapeYaml(node.sni)}"`] : []),
        ...(node.insecure ? [`    skip-cert-verify: true`] : []),
        ...(node.alpn ? [`    alpn: [${escapeYaml(node.alpn)}]`] : [])
      ].join('\n');
    }
    if (node.type === 'ss') {
      return [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: ss`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    cipher: ${node.method}`,
        `    password: "${escapeYaml(node.password)}"`,
        `    udp: true`
      ].join('\n');
    }
    return '';
  }).filter(Boolean);

  const proxyNames = nodes.map(node => `      - "${escapeYaml(node.name)}"`);
  const allGroupMembers = [`      - "自动选择"`, ...proxyNames, `      - DIRECT`];
  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...proxies,
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter(node => ['vmess', 'trojan', 'hysteria2', 'ss'].includes(node.type))
    .map(node => {
      const name = node.name.replace(/[ ,]/g, '_');
      if (node.type === 'vmess') {
        return `${name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      if (node.type === 'trojan') {
        return `${name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
      }
      if (node.type === 'hysteria2') {
        return `${name} = hysteria2, ${node.server}, ${node.port}, password=${node.auth || ''}, sni=${node.sni || ''}, skip-cert-verify=${node.insecure ? 'true' : 'false'}`;
      }
      if (node.type === 'ss') {
        return `${name} = shadowsocks, ${node.server}, ${node.port}, encrypt-method=${node.method}, password=${node.password}`;
      }
      return '';
    }).filter(Boolean);

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' + proxies.map(p => p.split('=')[0].trim()).join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    `; token-protected subscription`,
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

// ========== KV 短链接函数 ==========
function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value).split(/\r?\n/).map(l => l.trim()).filter(Boolean).sort().join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

// ========== API 处理 ==========
async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  try {
    const baseNodes = parseRawLinks(body.nodeLinks || '');
    const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');
    if (!baseNodes.length) throw new Error('没有识别到任何可用节点（支持的协议：vmess/vless/trojan/hysteria2/ss）');
    if (!preferredEndpoints.length) throw new Error('没有识别到可用优选地址');

    const options = {
      namePrefix: body.namePrefix || '',
      keepOriginalHost: body.keepOriginalHost !== false,
    };
    const nodes = buildNodes(baseNodes, preferredEndpoints, options);
    if (!nodes.length) throw new Error('节点组合后为空，请检查输入');

    const payload = { version: 1, createdAt: new Date().toISOString(), options, nodes };
    const dedupHash = await buildDedupHash(body);
    const dedupKey = `dedup:${dedupHash}`;

    let id = await env.SUB_STORE.get(dedupKey);
    if (!id) {
      id = await createUniqueShortId(env);
      const ttl = 60 * 60 * 24 * 7;
      await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), { expirationTtl: ttl });
      await env.SUB_STORE.put(dedupKey, id, { expirationTtl: ttl });
    }

    const origin = url.origin;
    const accessToken = env.SUB_ACCESS_TOKEN || '';
    const withToken = (target) => `${origin}/sub/${id}${target ? `?target=${target}&token=${encodeURIComponent(accessToken)}` : `?token=${encodeURIComponent(accessToken)}`}`;

    return json({
      ok: true,
      shortId: id,
      urls: {
        auto: withToken(''),
        raw: withToken('raw'),
        clash: withToken('clash'),
        surge: withToken('surge'),
      },
      counts: {
        inputNodes: baseNodes.length,
        preferredEndpoints: preferredEndpoints.length,
        outputNodes: nodes.length,
      },
      preview: nodes.slice(0, 20).map(n => ({
        name: n.name,
        type: n.type,
        server: n.server,
        port: n.port,
        host: n.host || '',
        sni: n.sni || '',
      })),
      warnings: accessToken ? [] : ['未设置 SUB_ACCESS_TOKEN，订阅链接无访问令牌保护'],
    });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: err.message }, 400);
  }
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  if (target === 'surge') return text(renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''), 200, 'text/plain; charset=utf-8');
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

// ========== 主入口 ==========
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }
    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }
    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }
    return env.ASSETS.fetch(request);
  },
};
