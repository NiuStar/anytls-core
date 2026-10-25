# 一键安装仅下载预编译二进制

## 行为变更

用户要求默认一键安装不下载源码。此前的 Python 预编译安装器复用了源码安装器的 release 选择器，把应用源码和对应源码包设为必需，并下载、保留它们；这不是运行二进制所必需。

修订后的可信 main 入口只取得必要元数据、`SHA256SUMS` 和当前架构 `darwin-arm64`／`darwin-amd64` 二进制包。完整安装、只读 `--check-download` 和新脚本的 `--update-only` 共用该下载策略。二进制包中已有的 LICENSE、THIRD_PARTY_NOTICES、licenses／NOTICE 和程序构建身份仍保留；不放宽来源、SHA、版本、架构、安全解包、备份或系统授权。

源码与对应源码仍在同一公开 Release 单独提供，不删除旧附件、已下载源码或历史备份；需要审计／重建时手动选择源码附件。显式源码构建入口 `install.sh` 仍是另一条路径，不在本次删除或改变其源码下载需求。

## 生效边界

- `curl -fsS https://raw.githubusercontent.com/NiuStar/anytls-core/main/get.sh | bash` 取 main 的新脚本，无需重新编译已有 `v2026-10-24-02` 程序；旧 Release 附件和标签保持不变。
- 已发行 CLI／WebUI 内嵌的旧 Python 更新器不随 main 脚本改变。当前已安装程序的网页更新仍按其内嵌版本运行，不能称其已被远程修复。后继新二进制发行才会包含修改后的共享脚本。
- 本次检查验证下载不安装助手、不替换生产程序、不重启 VPN；系统密码仍仅由实际安装时本机 sudo 处理。

## 官方脚本下载备用路径

外部 `get.sh` 取得 `install-control-helper.sh`，后者取得 `scripts/install.py` 与 `scripts/install-binary.py`：三次请求均优先 raw，curl 非零退出时才使用同仓库固定路径的 GitHub Contents API（`?ref=main`，`Accept: application/vnd.github.raw+json`）重下到同一临时文件，覆盖失败的部分响应。每次请求保持 `--fail`、HTTPS／TLS1.2、20秒连接／180秒总超时与原进度模式；API 同样失败时停止并清理临时文件，不调用失败的脚本。首行必须匹配已知脚本 shebang，拒绝空正文、API JSON 和 HTML；这是响应类型检查，不是独立签名验证。没有第三方镜像、新依赖、全局 DNS／CA 改动或跳验。

首次 raw 入口失败时，脚本尚未取得，不能自行回退；普通用户可直接使用官方 API 入口：

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/NiuStar/anytls-core/contents/get.sh?ref=main' | bash
```

这是 main 外部引导脚本修复，不修改产品二进制、版本或 Release 附件；保留参数透传、root 禁止、无 Go 安装与 `--check-download` 语义。API 限流和后续 Release 资产下载仍可能失败。自动回归以真实 Bash 加假 curl／uname／Python 执行整条链，验证回退、失败关闭、原参数及清理；属于隔离平台模拟，不代表 Mac 原生安装或网络恢复已经验收。

## 验证要求

arm64／amd64 各验证二进制附件与校验和的精确请求集合；缺少源码／对应源码不阻断，有来源错误／重复的所选二进制或缺校验和仍拒绝。完整安装和 update-only 保留许可证、旧程序备份和原配置；check-only 不执行子进程。干净源码 Python 全套、平台分支模拟、Mac 真实只读下载与公开 raw 脚本读回分别记录，完成后再追加实际证据。
