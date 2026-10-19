# anytls-core

基于 Go 的 macOS AnyTLS 客户端管理程序。

**当前版本：`v2026-10-19-01`。当前网络核心为独立的 sing-box 1.14.3 二进制；本仓库尚未内嵌、裁剪或复制 sing-box 源码。**

## 功能

- `anytls start / stop / status`：使用 macOS launchd 管理全局 TUN，启动需要本机 sudo 授权。
- `anytls config`：终端策略组/节点选择，↑/↓ 移动、回车或空格确认。
- YAML 节点、显式 select 策略组、有序规则、SHA-256 固定的本地 JSON 规则集。
- 服务器 `/32`、IPv6 `/128` 路由旁路，防止 AnyTLS 拨号进入自身 TUN。
- 启动核对路由及 HTTPS 出口，停止核对路由和 DNS 基线。

## 构建与安装

需要 Go 1.24+。目前正式适配目标为 macOS Apple Silicon；没有提供 Apple 签名或公证。

```sh
go test ./...
go vet ./...
GOOS=darwin GOARCH=arm64 go build -trimpath -o dist/anytls-macos .
```

在 Mac 上将文件安装到固定目录。**以下命令用于新安装；已有配置或同名命令时先备份，不要直接覆盖。**

```sh
mkdir -p ~/.anytls
cp dist/anytls-macos ~/.anytls/anytls-macos
cp config.example.yaml ~/.anytls/config.yaml
# 编辑 ~/.anytls/config.yaml，填入真实节点信息。
# 从官方 release 获取对应架构 sing-box 1.14.3，核验官方 SHA-256 后：
cp /path/to/verified/sing-box ~/.anytls/sing-box
chmod 755 ~/.anytls/anytls-macos ~/.anytls/sing-box
mkdir -p ~/.local/bin
ln -s ~/.anytls/anytls-macos ~/.local/bin/anytls
export PATH="$HOME/.local/bin:$PATH"
```

官方核心：[sing-box v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)。本仓库不携带第三方核心、真实节点密码或在线规则数据。

```sh
anytls config
anytls -network tun check
anytls start
anytls status
anytls stop
```

没有策略组时，首次用 `config` 选中节点，保存到 `config.yaml.selected`。有策略组时先选组再选成员；示例配置的 `节点选择.selected` 已明确指定。若没有单节点基座选择文件，可以先运行：

```sh
# 在安装目录执行；内容必须是 config.yaml 中的 AnyTLS 节点名称。
printf '%s\n' 'example-node' > ~/.anytls/config.yaml.selected
```

选择文件中的单节点是 DNS/bootstrap 基座；策略组的出口由各组 `selected` 决定。`config` 在服务运行时拒绝改选，请先 `stop`。

节点有 `skip-cert-verify: true` 时：`check/run` 需要显式 `-allow-insecure`；`start` 在本机终端要求输入 `yes` 确认 TLS 风险，然后提示 sudo 授权。不要将 sudo 密码交给脚本或聊天。

## 配置与分流

```yaml
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [example-node, DIRECT]
    selected: example-node
rules:
  - IP-CIDR,192.168.0.0/16,DIRECT
  - DOMAIN-SUFFIX,example.org,节点选择
  - DOMAIN,ads.example.org,REJECT
  - MATCH,节点选择
```

支持 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`RULE-SET` 和末尾唯一 `MATCH`；目标支持 AnyTLS 节点名、select 组、DIRECT、REJECT（MATCH 不支持 REJECT）。第一条匹配决定出口。不支持的语法直接报错，不静默忽略。不是完整的 Clash 配置兼容层，不支持 SS 出站。

本地规则集示例：

```yaml
rule-sets:
  private:
    path: rules/private.json
    sha256: '<该文件的64位小写SHA-256>'
    resolve-ip: true
rules:
  - RULE-SET,private,DIRECT,no-resolve
  - MATCH,节点选择
```

文件格式为 sing-box source JSON，`version: 3` 和非空 `rules`。引用时校验 SHA，启动复制进 root 私有服务快照，再使用快照本地路径。`resolve-ip: true` 表示非 no-resolve 引用前插入解析；上述显式 no-resolve 引用不会插入。远程 MRS/YAML 转换与定时更新**不是本版本内置能力**，须先离线审计转换；见 [docs/architecture.md](docs/architecture.md)。

## 运行文件

```text
~/.anytls/
├── anytls-macos
├── sing-box
├── config.yaml
├── config.yaml.selected
├── rules/                 # 可选本地规则集
└── service/               # root 私有当次运行快照；停止成功后清理
```

独立的 `check/run` 临时使用同配置目录 `runtime.json`，结束后清理。配置含明文密码；程序不限制 YAML 必须为 0600，但建议自行保护目录访问。

## 验证范围和限制

源码测试和静态检查已运行；macOS 上此前已验证 TUN IPv4 出口、服务器旁路、TCP、UDP DNS、退出后路由/DNS 恢复、CLI 和策略组 PTY。规则迁移候选已验证核心编译和代表性出站，**不能据此宣称全部策略组/节点已可用，或新完整分流已完成逐规则全局验收**。

没有断线 kill-switch、自动规则更新、开机自启、节点自动测速或无缝热切换。DNS、嗅探和多地址匹配不保证与 Mihomo 完全等价；应用 DoH/ECH、缓存可能影响域名可见性。TUN 节点拨号必须是固定 IP。当前 TLS 严格模式要求配置 CA PEM；跳过证书验证不能视为安全验收。

## 许可证与上游

本仓库源代码采用 [GPL-3.0-or-later](LICENSE)。sing-box 为独立上游组件，其许可证另有名称/关联限制；运行和分发须核对上游及依赖义务。Mihomo 仅作为先前离线 MRS 转换工具，不是正常运行依赖。本项目并非 sing-box 或 Mihomo 官方客户端。
