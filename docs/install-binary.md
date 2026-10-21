# 预编译 Release 安装器（macOS Apple Silicon）

此入口从固定官方仓库 `NiuStar/anytls-core` 的稳定 GitHub Release 下载
`darwin-arm64` 二进制，**不安装 Go、不本地编译、不运行压缩包内的 Python/shell**。
需要普通用户、macOS arm64、Python 3、curl 和可交互的本地终端。不要用 sudo
运行整个安装器；受限助手安装步骤会由候选程序调用系统 sudo 自行授权。安装器
不读取、保存或传输系统密码。VPN 不会因安装而自动启动。

## 使用

从可信 checkout 执行：

```sh
bash install-control-helper.sh
bash install-control-helper.sh --version v1.2.3
```

`v1.2.3` 仅为 tag 格式示例；请替换成实际包含二进制附件的稳定版本。不指定
`--version` 时使用最新稳定 Release。支持稳定 semver 和项目的 `vYYYY-MM-DD-NN`
格式，不接受 prerelease、分支、任意仓库或下载 URL。

根入口由可信 main 同时下载 `scripts/install-binary.py` 和其同目录
`install.py`。二进制安装器只通过 `__file__` 的 sibling 加载后者，复用 HTTPS
重定向约束、稳定版本校验、安全解压、配置初始化及备份/原子发布逻辑；不会从
Release 归档寻找 Python 模块。可信 bootstrap/main 和 GitHub HTTPS 都属于本次
信任边界；SHA256SUMS **不是独立签名，也不抵御 GitHub 发布权限被攻破**。

## 仅验证下载

```sh
python3 -I scripts/install-binary.py --check-download
python3 -I scripts/install-binary.py --check-download --version v1.2.3
```

本地需同时保有可信 `scripts/install.py`。检查模式可在非 macOS 上运行，使用
临时目录下载并校验二进制和完整对应源码附件，验证包结构、版本、manifest、
Mach-O 头及二进制摘要；输出 JSON 的 `download_verified: true` 和
`executed: false`。**不运行二进制、不调用 helper、不创建应用目录、配置或 PATH
链接**。临时树退出即清理；可设置 `TMPDIR` 指定临时目录。

此模式只证明发布内容与其 HTTPS 下载的校验材料一致，不证明 macOS 可执行、
助手权限安装、真实 TUN、WebUI 或网络行为。安装前的 `version` 命令不属于检查
模式。

## Release 合同

同一个稳定 tag 必须存在以下四个精确附件；没有二进制的旧 source-only Release
明确失败，不会回退编译：

- `anytls-core-TAG-darwin-arm64.tar.gz`
- `anytls-core-TAG-source.tar.gz`（精确应用源码、构建脚本及补丁）
- `anytls-core-TAG-corresponding-source.tar.gz`（应用源码、实际链接依赖源码和 Go 源码）
- `SHA256SUMS`（上述三个归档必须各有唯一 SHA256 行）

所有初始 API 和附件 URL 固定官方仓库及精确 tag；附件仅接受可信 GitHub HTTPS
重定向域。二进制包前缀必须为 `anytls-core-TAG-darwin-arm64/`，至少包含：

```text
bin/anytls-macos
VERSION
BUILD-INFO.json
config.example.yaml
LICENSE
THIRD_PARTY_NOTICES.md
```

允许附带 `licenses/` 等额外普通文件，但不执行它们。`VERSION` 必须为 plain
`TAG`（可有一个末尾换行），`BUILD-INFO.json` 至少包含：

```json
{"source_commit":"<40位小写Git commit>","binary_sha256":"<64位小写SHA256>"}
```

重复 JSON 字段拒绝；`source_commit` 必须等于官方 `/commits/TAG` 的结果；
`binary_sha256` 必须等于流式计算的实际文件摘要。二进制要求 thin arm64
Mach-O executable 头；这不替代 macOS 平台加载及实际执行。归档流式展开，拒绝
越界、错误前缀、重复成员、file/directory 碰撞、符号/硬链接及特殊文件；不继承
可执行位。源码包验证整体 SHA256 并保留，不执行或展开其内容。

## 安装顺序与更新边界

固定普通用户路径如下，不提供任意系统目录覆盖选项：

- 二进制：`~/.anytls/anytls-macos`
- 配置：`~/.anytls/config.yaml`
- PATH 链接：`~/.local/bin/anytls` → 上述二进制
- 旧二进制备份：`~/.anytls/backups/`
- 本次包内许可证、manifest、原始完整源码包、SHA256SUMS：
  `~/.anytls/releases/TAG-<随机标识>/`

先拒绝应用目录 symlink、已有非普通目标/配置，以及与其他程序冲突的 PATH
入口。全部下载验证成功后，将候选复制为同一 appdir 内随机的普通文件
`.anytls-bin-candidate-*`，赋 `0700` 后执行 `version` 校验精确 tag。
已有配置原字节保留；首次仅复制包内真实 `config.example.yaml` 为 `0600`，
不生成假节点/凭据。仍需输入实际服务器、密码与 CA 等信息才能正常使用 VPN。

在任何 root 安装之前创建/检查 CLI 链接；初次安装时它会暂时指向尚未发布的
目标。候选以 `/dev/tty` 为 stdin 执行 `helper install`，由原生 sudo 授权；
该命令的认证 readiness 和随后的 `helper status` 都成功后，才先备份实际旧
二进制，再原子发布并再次执行 `version`。不自动执行 VPN 的 start/reload/stop。

所有归档校验成功后，先完整保留并读回核对许可证、NOTICE、源码、CCS 和摘要材料；保留失败不会执行候选或改变旧程序／配置。随后将候选复制到同一 appdir 内并验证版本。
安装不是跨用户文件和 root helper 的原子事务：首次创建的配置/链接可能保留；helper 已成功后
若备份/发布或最终 version 失败，helper 或用户二进制可能已经
更新。不要把失败当作自动回退；检查 `anytls helper status`、当前
`anytls version` 与备份后再决定恢复或重试。安装/重启阶段持有
`~/.anytls/.install.lock` 的非阻塞独占锁（拒绝符号链接、权限 `0600`），
并发安装器会明确失败。

**安装成功默认自动关闭旧 WebUI 并启动新版，首次安装也会启动。**
固定地址为 `http://127.0.0.1:18089/`，不迁移或停止其他端口上的旧 WebUI。
在 helper 安装及发布前，使用系统 `lsof` 查询 18089 监听 PID，并通过完整
`ps` 信息核对当前 UID、启动时间和精确目标路径命令；只接受
`~/.anytls/anytls-macos webui`（可带 `--port 18089` 或 `--port=18089`）。
外来占用、多监听或未知参数一律拒绝继续，不根据 basename、子串或历史
`webui.pid` 杀进程；历史 pidfile 完全不作为权限依据，也不更新它。

仅在 helper 安装/status、原子发布和新目标 version 都成功后，重新核对旧进程
身份与启动时间，向明确识别的旧 WebUI 发送一次 `SIGTERM`，有界等待旧进程
消失且端口空闲；身份变化不再发信号，超时不使用 `SIGKILL`。helper 失败不会
关闭旧 WebUI。新进程以 `webui --port 18089` 独立会话启动，stdin 为 `/dev/null`，
stdout/stderr 追加到 `0600` 的 `~/.anytls/webui.log`。必须确认监听 PID 等于
新子进程 PID，且首页 HTTP 200 含实际控制台标记，并再次确认端口归属，才报告成功。

如果发布后无法停止旧 WebUI 或新版启动/就绪失败，会返回非零并明确报告
`binary installed but WebUI start failed`；二进制已经安装，不伪称整笔回滚。
启动失败只尝试 TERM/等待本次创建的子进程，不操作未知 PID。请检查日志、端口及
`anytls version` 后重试。WebUI 重启会清空登录会话，需重新登录；既有应用密码、
节点密码和配置仍保留。

**整个安装流程不调用 VPN 的 stop/reload/start，也不向 VPN 或 helper 发信号。**
正在运行的 VPN 仍使用此前快照，何时显式应用/重载由用户决定；不会悄悄重连
VPN、改变路由或 DNS。此行为由可信 main 的 Python 安装器实现，不要求新二进制 tag。

## 本地单元验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/install_binary_test.py
```

测试使用实际临时 tar/文件及模拟 transport/subprocess/HTTP，禁止真实网络和
未模拟的 subprocess.Popen；覆盖校验材料、URL、路径、版本、manifest、候选权限、
配置保留、链接冲突、助手失败及真实备份/原子发布文件操作，并覆盖 WebUI 首次
启动/安全重启、外来 UID/路径/参数、陈旧 pidfile、启动时间变化、TERM 超时、
子进程退出、错误监听 PID、HTTP 标记与就绪竞态、失败清理及安装锁。属于
**UNIT-SIMULATED**，不是一次真实 macOS 特权安装验收；仍需真实 Mac 上验证系统
lsof/ps 输出、官方二进制启动和 VPN 运行状态不变。
