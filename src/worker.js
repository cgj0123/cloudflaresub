// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

// Cloudflare Worker: KV short link subscription + access token protection
// Supports: vmess, vless, trojan, hysteria2, shadowsocks

// worker.js (修复版，仅展示核心改动，完整文件请合并)

// ---------- 修复 parseHysteria2 ----------
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
    auth: auth,                 // 可能为空字符串
    sni: params.get('sni') || '',
    insecure: params.get('insecure') === '1' || params.get('insecure') === 'true',
    alpn: params.get('alpn') || '',
    path: params.get('path') || '',
    obfs: params.get('obfs') || '',
    // 以下为内部固定字段
    tls: true,
    network: 'udp',
  };
}

// ---------- 修复 encodeHysteria2 ----------
function encodeHysteria2(node) {
  // 避免 auth 为空时出现 "@" 符号
  let authPart = '';
  if (node.auth && node.auth.includes(':')) {
    authPart = `${node.auth}@`;
  } else if (node.auth && !node.auth.includes(':')) {
    // 仅用户名，无密码
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

// ---------- 修复 parseShadowsocks (兼容更多格式) ----------
function parseShadowsocks(link) {
  let content = link.slice('ss://'.length).trim();
  let name = '';
  const hashIndex = content.indexOf('#');
  if (hashIndex !== -1) {
    name = decodeURIComponent(content.slice(hashIndex + 1));
    content = content.slice(0, hashIndex);
  }
  let method, password, server, port;
  // 尝试 SIP002 标准格式: method:password@host:port
  if (content.includes('@')) {
    const [auth, hostport] = content.split('@');
    [method, password] = auth.split(':');
    const [host, p] = hostport.split(':');
    server = host;
    port = parseInt(p) || 443;
  } else {
    // base64 编码格式 (如 ss://YmYtY2ZiOnRlc3Q@192.168.100.1:8888)
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

// ---------- 修复 buildNodes 中的 keepOriginalHost 对新协议的影响 ----------
function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
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
        // hysteria2 和 ss 不需要 host/sni，不做任何处理
      } else {
        if (node.type === 'vmess' || node.type === 'vless' || node.type === 'trojan') {
          // 如果原本的 host/sni 等于原始服务器域名，则替换为优选 IP（可选，但不推荐）
          if (!node.host || node.host === node.server) newNode.host = ep.server;
          if (!node.sni || node.sni === node.server) newNode.sni = ep.server;
        }
      }
      output.push(newNode);
    }
  }
  return output;
}

// ---------- 在 handleGenerate 中增加详细错误返回 ----------
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

    // ... 后续 KV 存储和返回 (保持不变)
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
      urls: { auto: withToken(''), raw: withToken('raw'), clash: withToken('clash'), surge: withToken('surge') },
      counts: { inputNodes: baseNodes.length, preferredEndpoints: preferredEndpoints.length, outputNodes: nodes.length },
      preview: nodes.slice(0, 20).map(n => ({ name: n.name, type: n.type, server: n.server, port: n.port, host: n.host || '', sni: n.sni || '' })),
      warnings: accessToken ? [] : ['未设置 SUB_ACCESS_TOKEN，订阅链接无访问令牌保护'],
    });
  } catch (err) {
    console.error(err);
    return json({ ok: false, error: err.message }, 400);
  }
}
