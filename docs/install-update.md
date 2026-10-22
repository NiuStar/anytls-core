# 网页与 CLI 预编译更新（v2026-10-22-06 起）

网页“安装更新”与 `anytls update` 共用官方预编译包更新链，支持 macOS arm64／amd64，**不需要 Go、不回退源码编译**。当前控制台（内存）、已安装程序（磁盘）、最新版本分别显示；重复检查仍保留需重启状态。

更新保留配置、选择与应用密码，校验官方同 tag 程序、应用源码、对应源码及 SHA256SUMS。旧程序备份须独立读回 SHA 后才原子替换。网页更新不调用 sudo、特权助手安装、PATH 修改、WebUI 重启或 VPN 控制。安装接纳后关闭页面不取消发布，CLI 对唯一 Python publisher 设独立35分钟上限，网页动作锁保持至 Wait 与独立版本读回完成。替换后核验失败不能保证旧文件未变，不自动回滚；保留备份等待核对。SHA256SUMS 不是独立签名。

```sh
anytls update --check
anytls update
anytls version
```

默认仅同版本体系严格递增；显式 `--version` 可主动指定实际稳定标签。CLI 五字段 JSON 中 `source_only` 现按当前程序架构的完整预编译材料判断，不再固定为 true。网页错误区分检查、Python、材料、下载、校验、发布与替换后核验失败，不透传工具日志。

首次给旧版接入修复需一次受控用户程序替换，此后可直接使用网页链路；外部安装脚本不是网页故障的替代修复。原生及真实浏览器验证见 [版本说明](releases/v2026-10-22-06.md)，首次预编译安装见 [安装说明](install-binary.md)。

## 历史：一键安装与源码 Release 升级（v2026-10-22-05及之前）

以下仅保留旧源码入口及历史验证边界，**不描述当前网页／CLI update**。

旧源码安装流程仅支持 **macOS arm64 / embedded_core**；其安装器不假设有预编译二进制，也不会上传本机二进制。

## 初次安装 / 重装

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/NiuStar/anytls-core/main/install.sh | bash
```

固定版本（必须是含此安装器及 version 命令的新 Release）：

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/NiuStar/anytls-core/main/install.sh | bash -s -- --version v2026-10-21-02
```

也可先下载、审阅官方 `install.sh` 后运行。脚本只取固定官方仓库，不接受 URL 作为版本。`VERSION=v... bash install.sh` 同样支持固定版本。只接受真实日历日期的 `vYYYY-MM-DD-NN`（月份、日、末尾序号必须两位）或无前导零的稳定 `vMAJOR.MINOR.PATCH`；不接受预发布标记。

依赖 Python 3（stdlib）和 curl。缺 Python 时给出 python.org 安装地址并退出，不运行远程包管理器。检测 PATH、Homebrew、`~/sdk/go1.26.8` 和应用私有目录中的**精确 Go 1.26.8 darwin/arm64**；没有时，运行官方安装器即明确授权下载官方 Go manifest 中固定版本的 arm64 archive，逐流 SHA256 校验后仅安装到 `~/.anytls/toolchains/go1.26.8`。不修改系统 Go、不升级系统软件。

默认正式程序为 `~/.anytls/anytls-macos`，与现有 servicePaths 一致；配置仍为同目录 `config.yaml`，不移动配置。仅在不存在时以 0600 创建 `config.yaml` **示例**；示例地址、密码占位符和 CA 路径不可直接使用。用户须填写自己的节点凭据/CA，再执行 `anytls config` 选择节点。已有配置、selected、规则、CA、auth.json 和 WebUI 密码不覆盖。重装只更换程序，不自动停止/重启 VPN。

创建 `~/.local/bin/anytls` → `~/.anytls/anytls-macos` 符号链接；若该位置是别的程序/不匹配链接则拒绝覆盖。请将 `~/.local/bin` 加入 PATH。

## 升级

```bash
anytls update --check
anytls update
anytls update --version v2026-10-21-02
anytls update --check --version v1.2.3
anytls version
```

`--check` 只访问 GitHub Release API，stdout 只有 JSON：

```json
{"current_version":"v2026-10-21-01","latest_version":"v2026-10-21-02","update_available":true,"source_only":true,"release_url":"https://github.com/NiuStar/anytls-core/releases/tag/v2026-10-21-02"}
```

示例是字段协议，不是本次在线查询结果。未指定版本时固定 `/repos/NiuStar/anytls-core/releases/latest`；不接受 draft/prerelease。`update_available` 在未指定版本时仅表示同一版本体系的严格递增：日期版按有效日历日期及两位序号比较，semver 按三个整数比较。旧 latest、相同版、开发版或日期/semver 跨体系不自动升级/降级；显式 `--version` 才允许用户主动回退或切换体系。默认不设定时任务，不后台轮询。CLI 升级缺 Go 时退出，提示重新运行官方安装器（`--install-toolchain` 是安装器选项，不是 CLI update 选项）；不默装系统软件。

bootstrap 的 install.py 和可信 wrapper 始终从官方 main 获取，`--version` 只指定 Release 源码，不要求旧 tag 内已存在安装器。若当前 latest 是缺少 `version` 命令的旧 Release，安装会明确失败，不输出 Installed，不发布构建产物，保留已有程序与配置；须待支持该命令的新 Release，或显式指定已支持版本。本次未增加 `--source-dir` 参数。禁止 root/sudo 运行安装器。

旧安装名 `appdir/anytls` 仍被 CLI updater 明确允许，更新原路径，不改配置位置。重装旧命名时可显式运行已审阅安装器 `--target "$HOME/.anytls/anytls"`；默认安装不会悄悄覆盖指向旧命名的 PATH 链接。

版本从 `//go:embed VERSION` 在编译时捕获；发版前必须更新 VERSION。解压源码 VERSION 必须等于 Release tag，构建完成后还须由新程序 `version` 返回同一 tag。

## 下载与代码执行信任边界

- 固定 HTTPS GitHub API、官方仓库 release URL、同 tag 的精确源码资产与 `SHA256SUMS`；API 不接受重定向，资产重定向只允许 GitHub 官方 release CDN。Go 只允许 go.dev/dl.google.com。
- 同一个 Release 的 SHA256SUMS 防损坏，但**不是独立认证签名**；不能防 GitHub 账户/Release 及传输信任同时被攻破。目前未实现签名选项，不把 checksum 或 target commit API 结果说成签名验证。`/commits/TAG` 只解析并报告 API 当前目标 commit，不声称源码附件逐文件等于该 Git tree 或防 tag 被移动。
- 源码必须使用 `anytls-core-TAG/` 前缀。流式 tar 解压只允许普通文件/目录；拒绝绝对路径、`.`/`..`/空组件、反斜线、控制字符、symlink、hardlink、特殊文件、重复条目和文件/目录冲突。不执行 archive 的 shell/Python 脚本，所有源码解压文件清除执行权限。
- 构建使用当前安装 CLI 内嵌的可信 `go-patched.py`（首次安装为官方固定脚本来源），不会执行 archive 内的 Python wrapper；以 Python `-I` 隔离模式运行，防止归档 scripts 目录中的同名 Python 模块劫持可信 wrapper 的 stdlib imports。主动 install/update 本身授权编译并运行新版本 Go 代码进行版本核验；Go build 不是恶意源码沙箱。
- 精确 Go 1.26.8、绝对 GO_BIN、GOTOOLCHAIN=local、GOWORK=off、GOFLAGS 空、GOENV=off、独立 GOCACHE/GOMODCACHE/GOPATH、固定官方模块代理与 sumdb；完整 tags 为 `with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core`。不覆写 HOME/系统环境。
- 不人为设置下载字节/解包字节容量上限；使用流式下载+hash、网络超时、构建超时及实际磁盘/I/O 错误。现有可信 wrapper 自身的上游固定模块完整性策略未在本任务改动。

## 备份、失败、运行中的进程

临时目录仅在 appdir 内用随机目录创建，仅清理本次拥有的目录。构建/下载失败不替换旧程序。实际旧可执行文件逐流备份到 `~/.anytls/backups/update-UTC日期-唯一值-anytls`，fsync 后同文件系统原子 rename 仅替换 `appdir/anytls-macos`（或明确选定的旧名 `appdir/anytls`）；backup/rename 错误上报，不覆盖配置。源码、上游 LICENSE/NOTICE、Release sums 留在 `~/.anytls/sources/TAG-唯一值`，模块与构建 cache 留在应用目录，可供后续构建复用。保留源码不等于已完成二进制再分发许可证审查。

磁盘替换不改变当前进程内存：现有 VPN 仍运行私有快照，须用户主动 `anytls reload`；**WebUI HTTP 进程仍是旧代码，须用户手动退出/重新启动 WebUI**。不自行 kill WebUI/server，不自动 launchd 停启。独立停止 VPN/服务仍应遵守原命令权限/恢复检查。

## 本地验证边界

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p install_test.py -v
bash -n install.sh
```

Python tests（24 项）标为 UNIT：强制禁止 socket 和 Popen，使用内存 transport、临时真实归档/文件，覆盖安全路径、hash、稳定版本、异常 JSON、备份/原子失败、配置保留、PATH 冲突、私有 Go 官方 manifest 协议和失败清理；新增首次安装/重装/旧名兼容真实文件流、正式名 PATH 链接、缺 version/版本不符/编译/hash 失败发布前保留、重定向跨信任域及 root 拒绝测试。编译和新程序执行仍 mock，不将 fixture 的非可执行数据称作真实构建或正式升级。

本 Linux 工作环境未运行 Go 编译/测试（**Go NOT_RUN**）；本次仅修改 `update*.go`，其格式化及测试由父任务在 Mac 统一完成。`update_test.go` / `version_test.go` 需父任务在 Mac 使用固定 wrapper 运行。Mac arm64 全量构建、真实安装/重装/升级与旧 WebUI 存活验证仍待执行；开发实现不授权生产安装、SSH、真实配置改写或启动服务。
