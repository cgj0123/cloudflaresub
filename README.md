<h1 align="center">
  <img src="./public/icons/auto.svg" alt="CloudflareSub Logo" height="40" align="absmiddle" /> CloudflareSub
</h1>

<p align="center"><em>一个轻量化的优选IP订阅器，支持多协议与智能CDN检测</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-2ea44f" alt="License MIT" />
  <img src="https://img.shields.io/badge/platform-Windows-0078D6" alt="Windows" />
  <img src="https://img.shields.io/badge/platform-macOS-111111" alt="macOS" />
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux" />
  <img src="https://img.shields.io/badge/runtime-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white" alt="Cloudflare Workers" />
  <img src="https://img.shields.io/badge/status-active-00C853" alt="Status Active" />
</p>

## 功能特性

- 支持 **VMess**、**VLESS**、**Trojan**、**Hysteria2**、**Shadowsocks** 节点解析与重建
- 支持 Base64 订阅文本自动展开
- 支持 `host[:port][#remark]` 格式的优选地址（IP 或域名）
- **智能 CDN 检测**：自动判断节点域名是否使用 CDN，若未使用 CDN 则自动回退到原始域名，避免无效替换
- **自动优选 IP**：当用户未提供优选 IP 时，自动从原始域名解析 A 记录并填入
- 结果写入 Workers KV，生成 `/sub/:id` 短链（7 天 TTL）
- 相同输入自动去重（基于内容哈希）
- 支持 `SUB_ACCESS_TOKEN` 访问令牌保护
- 支持导出：Raw（Base64）/ Clash（YAML）/ Surge（文本）

## 项目结构

```text
cloudflaresub/
├─ src/
│  ├─ worker.js      # Worker 入口（API + 订阅输出）
│  └─ core.js        # 解析/渲染核心函数（测试使用）
├─ public/           # 前端静态资源
├─ tests/smoke.mjs   # Smoke test
├─ wrangler.toml
└─ package.json
