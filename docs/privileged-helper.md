# 本机控制助手安装

仅 `embedded_core` macOS 构建支持安装。在普通用户的本机终端执行：

```sh
/absolute/path/anytls helper install
/absolute/path/anytls helper status
```

安装会调用 `/usr/bin/sudo -- /absolute/physical/self helper-install-root UID HOME`。管理员密码由系统终端处理；程序不读取、保存或经 HTTP 传输密码，不修改 sudoers。内部 root 命令只接受固定 UID、HOME 两个参数；没有自定义源程序、配置或目标路径参数。重复安装或更新 helper 仍需系统授权，普通 `anytls update` 不更新 root helper。尚无卸载命令。

## 固定文件与权限

| 文件 | 权限 |
| --- | --- |
| `/Library/PrivilegedHelperTools/com.nousresearch.anytls-control` | root，0755 |
| `anytls-control`（上述目录内） | root，0755 |
| `registration.json`（同目录） | root，0600 |
| `control.log`（同目录） | root，0600 |
| `/Library/LaunchDaemons/com.nousresearch.anytls-control.plist` | root，0644 |

授权记录只有 `uid`、`config`、`home`。UID 必须大于零；HOME 必须精确匹配系统用户数据库、由该用户所有、非 symlink。源程序必须为 HOME 下的物理 regular executable，固定配置为源程序同目录 `config.yaml`，不能为 symlink。源路径与 home 祖先均拒绝 symlink。用户配置及其目录仍可由用户编辑，这是既有 Plan B 策略，并非对恶意同 UID 的完整沙箱。

目标全部祖先必须为 root-owned、不可 group/world 写的真实目录。socket 固定 `/Library/PrivilegedHelperTools/com.nousresearch.anytls-control/run/control.sock`，父目录root-owned 0711，socket为授权用户0600并核验内核peer身份。避开部分Mac上group-writable的/private/var/run，不放宽祖先校验或修改系统目录权限。

## 启动与回退

plist 只执行 root-owned `anytls-control helper-serve`，不再执行用户 app。独立 label 为 `com.nousresearch.anytls-control`，RunAtLoad 和 KeepAlive 均开启，ThrottleInterval 为 10 秒。WorkingDirectory 固定为授权 config 目录，以保持相对 CA 的原有语义；标准输出与错误写入 root 私有日志。

安装在同一个源 handle 捕获字节并 hash；发布使用同目录临时文件、指定权限、文件 fsync、rename、目录 fsync。升级先保存 `anytls-control.backup`。仅 bootout helper label，不操作 VPN label。发布、bootstrap 或 launchctl readback 失败会恢复旧 executable、registration、plist，尝试重新 bootstrap 旧 helper，保留原错误和回退错误。若不能确认卸载新 helper，则明确报 rollback blocked，不在运行中的新实例下面替换文件。无旧版本时只删除本次尝试的目标，不递归删除目录或任意父路径。

root installer 在事务提交前保留旧 executable、registration、plist 的内存副本，并执行候选 readiness gate：读取固定 helper label 的 launchctl print，要求匹配 label、running 和 PID；随后直接执行受保护的固定 `anytls-control helper status`，子进程降权至授权普通 UID、系统 primary GID，supplementary groups 仅保留 primary GID。不使用 sudo -u、shell 或用户 app 路径，不接受额外 flags；环境清空后只设置用户 HOME 和固定 PATH，工作目录为 `/`。status 子进程通过既有 ordinary-UID/socket 校验、kernel root peer 认证和启动 SHA 对磁盘 SHA 校验；root 再解析完整响应，要求 `ok=true` 且 `helper_sha256` 等于本次候选捕获字节 SHA。注册成功但未运行、socket 不可用、身份/SHA/降权失败均不能提交。轮询总体 context 为 15 秒，每轮 launchctl/status 共用最多 4 秒预算；这是有界超时策略，不是实时调度保证。

readiness 失败先 bootout 候选，成功卸载后才恢复全部旧文件并 bootstrap 旧 helper；初装只删除本次目标。候选 bootout 失败时返回原错误与 rollback blocked，不在 job 状态未知时覆写文件，保留旧 executable backup；任何文件恢复错误也不会 bootstrap 混合版本。sudo 返回后仍保留原普通用户 socket status/SHA readback，成功才输出 JSON；这层检查不替代 root 事务内 gate。root 本身不作为 socket client，server 继续拒绝 root client。`helper status` 是只读路径，不尝试安装、启动或修复；缺失时明确提示本机安装，其他错误保持 unavailable 而非冒称未安装。

## 验证边界

`control_helper_install_test.go` 覆盖 plist XML/固定参数、用户路径与 symlink 拒绝、祖先权限拒绝、原子文件替换与错误清理，以及发布/启动/验证失败后的初装清理和旧版恢复。新增 readiness callback 成功/失败、print 注册但 waiting/exited、恢复前候选卸载顺序、卸载失败禁止覆写/保留 backup，以及固定只读 child 的 UID/GID/groups/环境和响应 OK/SHA 校验。测试通过与否须由原生运行回执确认；这些 fixture 不执行真实 launchctl。macOS 原生 gofmt、test、vet、plist 的 `plutil -lint` 由集成验收运行。真实 root 安装、socket readback、VPN 生命周期须在用户本机另行验收，不能由静态检查或 fixture 声称完成。
