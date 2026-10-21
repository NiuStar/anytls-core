# 管理台候选验收 — v2026-10-21-02

此为源码开发分支交付，不是正式 Release／正式安装。基线 `c1d1118311bd96df465ac348e0a13e1efb38e7ab`。父审与独立质量审查绑定 29 文件原字节 manifest；审查后未更改这些文件。

## 已执行

- Mac Studio 原生 Go 1.26.8、darwin/arm64、CGO=0，认证 wrapper，全 tags：`with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core`。
- 最终 targeted、全量 test、vet、build 全部 rc=0；全量 **166 顶层 PASS / 332 子测试 PASS / 3 顶层 SKIP**。跳过不算通过。
- 候选可执行文件：30,291,586 bytes，SHA256 `acca16dd8b0afc33b477b3dd27a72a2913e58ac278be5708a9658ffa1ff00247`；`version` 实际返回 `v2026-10-21-02`。
- 安装器 24 项 Python UNIT 通过、`bash -n install.sh` 和 `git diff --check` 通过。
- 最终二进制启动隔离 WebUI，真实 Chromium 验证 admin 登录、策略组保存、节点同值保存 changed=false、私密 YAML 显式读取与同值保存、规则列表、退出、390px 窄屏抽屉；无 JS error、无横向溢出，最终窄屏像素检查无遮挡。
- Mac 临时 HOME/appdir 使用本地受控 Release metadata/transport，两次**真实 Go 编译**、新 executable version、首次安装、重装、旧 executable 备份、PATH symlink、配置／选择／测试凭据保留均通过。transport/metadata 为 synthetic fixture，编译／文件发布并非 mock。
- 普通 `osascript -e SCRIPT -- argv...` 参数传递真实通过；这不是管理员授权／系统服务测试。
- 临时 WebUI 只在 28089 监听，验收后按确切 PID/commandline 停止，确认端口释放，专用 SSH tunnel 已关闭；未操作正式 launchd/TUN。

## 已修复并回归

- 正式文件名 anytls-macos 与 updater 白名单不匹配。
- 默认 update 不再把 older latest 当升级，显式指定版本才允许回退。
- 网页更新接纳后同步持有自有 CLI 至 Wait 和独立版本核验，不因 HTTP 取消只杀 CLI 而提前释放动作锁；不承诺强杀／崩溃恢复。
- 节点表单同值保存不再补空 SNI 或重写 YAML，alias/shared guard 在 no-op 比较前。
- 节点旧编辑器负例真实返回 changed=true；升级取消负例首次 helper dispatch 错误仅为 fixture failure，未计为有效 RED，修正 helper 的后继负例能够到 ready 后被取消杀死、无法在 gate 后产生 publish ack。历史失败不覆写。

## 审查与证据

- 独立静态质量复核：`PASS_SCOPED_QUALITY`，无新的可复现 P1/P2，SC-01 / SC-03 关闭。
- 29 文件 manifest 原字节 SHA256：`2b0e2a4475174349dbe58f0418d039826507b5c5d850d6d8b93cd6aa250e9293`。
- 审查是静态审查，不冒称 reviewer 实跑。原生日志、binary、安装结果由父独立读回；本地证据保留在 `artifacts/operator-console-v2/`，不提交公网。
- native source shadow 的 README/CHANGELOG/.gitignore/CI 为旧基线文档；产品 Go、嵌入页面、VERSION、installer 的共有输入与最终工作树 SHA 一致。这四项随后仅作文档／CI／忽略规则修改，不把 native receipt 称为全量29文件同字节。

## 未执行／不可外推

1. 未执行本轮正式 TUN start/stop/reload 或原生管理员 GUI 授权；需在本机使用权限，不能据单元测试称真实 VPN 重载完成。
2. 新版尚未发布，在线一键安装／官方 Release 升级链没有最终验证；当前旧 Release 无新增 version 命令，安装器会失败关闭而不是伪造成功。
3. 未替换 `~/.anytls/anytls-macos`，不更改真实配置或当前连接。候选 `VERSION` 不代表已发标签。
4. 源码 Release 不含二进制分发／Apple 签名／公证；SHA256SUMS 不等于独立签名。安装后 WebUI 须退出重启，VPN 须手动 reload。

使用说明：[WebUI](webui.md)、[安装／升级](install-update.md)。
