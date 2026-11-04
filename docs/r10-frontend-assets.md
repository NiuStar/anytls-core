# R10 front-end static assets

新增服务路径固定为 `/product.js` 与 `/product.css`，分别对应 `web_assets/product.js`、`web_assets/product.css`。现有 `/index.html`、`/app.js`、`/style.css` 继续使用；`runtime.js`、`startup.js`、`dns.js` 保留既有解析器及读回边界。

静态 allowlist / embed / gzip-brotli transfer 与 Go 测试清单由父 owner 接线。新增 JS 不应通过 fallback HTML 冒充成功。

## VPN traffic 接线

- GET `/api/v1/traffic` 直接消费 `internal/trafficstats.Response`，不使用旧 metrics 的全 null traffic 占位。每次请求带 `X-AnyTLS-Origin: location.origin`，fetch 保持 same-origin credentials / no-store / redirect:error；浏览器自动设置 Fetch Metadata，真实 handler 同源验收由父 owner 执行。Playwright route 拦截层不提供 `Sec-Fetch-Site`，不把该层缺失当服务端证明。
- canonical uint64 十进制字符串先验格式、范围，累计和纳秒差保留 BigInt；Mbps 为实际区间 bytes × 8 / elapsed ns，GB 使用十进制，累计精确 bytes 在 title 中可读。
- 严格检查字段、schema、header binding、RUNNING、SDK_ROUTED_PAYLOAD、实际历史顺序/跨度/数量、累计界限、15 秒新鲜度；首采样无 rate，不当成零网速；饱和保留累计但无速率。
- 实际完成历史区间单独绘制，不插值、不补零、不跨实例求差；首次/空记录/旧 helper UNAVAILABLE/503/过期时清除旧值。
- 与 HTTPS metrics 同样由可见 overview、route epoch、session generation、AbortController 和 timeout 所有；离页、隐藏、pagehide、退出均取消并清空。过期定时器独立清空，无需等待下一次请求。
- HTTPS latency / success ratio 仍是固定端点系统路径检查，不能声称 VPN 出口或全部网络健康。流量只代表 SDK routed payload，不代表全设备或 wire bytes。
- 订阅 `selection_invalid` 消费候选 choices，要求显式选择，apply 携带 `selected` 以及原有 target/candidate version；不新增浏览器 reload 或 save。

## 本轮证据

证据根目录：`/workspace/anytls-r10-product-evidence-r2/frontend`；旧 `r10-frontend-evidence` 未覆盖。

- `baseline/results.json`：改动前 170 checks / 47 screenshots。
- `final/results.json`：当前 236 checks / 53 screenshots，1440 / 390 两宽度，16 routes、抽屉、订阅候选、traffic observed/empty/unavailable，零 pageerror。证据标签 `SYNTHETIC_API_FRONTEND`，不证明真实 Go handler / native VPN。
- `node-regression-final.log`：原有五份 Node VM/lifecycle 回归合计 77/77，通过。
- Node syntax 和 owned-path `git diff --check` 通过。
- 历史 `web_runtime_status_browser_test.mjs` 已重试：其旧 overview 内 runtime-panel 截图在 R10 专属 debug 路由下不可见而超时（`runtime-browser-fonts.log`）；未擅改非所有权旧测试。未设置 fontconfig 的尝试在 browser navigation 关闭，保留原始日志。`startup-browser-fonts.log` 记录旧 startup 套件在等待 overview 的 `startup-copy` 自动启用时超时；它假设 overview 自动读取 startup，和 R10 debug-only 所有权不一致。两份历史浏览器套件不计入通过项，需父 owner 决定迁移测试路由。
- 像素审查留给父 owner；本轮功能通过不等于视觉批准。用户设计/原型许可、代码、真实服务端接线、macOS/native VPN 验收分别独立。

重跑：

```sh
R10_EVIDENCE=/workspace/anytls-r10-product-evidence-r2/frontend/final /home/hermeswebui/.hermes/node/bin/node web_r10_product_browser_test.mjs
/home/hermeswebui/.hermes/node/bin/node --test web_runtime_status_test.mjs web_rules_list_only_test.mjs scripts/web_update_restart_test.mjs web_status_lifecycle_test.mjs web_update_observation_test.mjs
```
