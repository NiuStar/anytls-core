# 网页预编译更新修复

状态：实施规格，未验收、未发布。基线 50ede36，当前用户程序 v2026-10-21-06。

## 根因与目标

网页 POST /api/v1/update 调用自身 CLI update --version，CLI 内嵌 source installer，只接受精确 Go 1.26.8；目标 Mac 的真实 find_go 返回 None。HTTP 丢弃子进程错误统一显示 UPDATE_UNAVAILABLE。检查更新成功不代表安装成功。修复 CLI 与网页的共同更新链，不让用户改用安装脚本。

## 唯一安装路径

- CLI 内嵌当前可信 scripts/install-binary.py 与其 sibling install.py，写到 appdir 的自有临时目录，以 python3 -I 执行本地可信入口。不下载或执行 main 分支脚本，不执行归档脚本，不回退源码编译，不启动 Go。
- 在 binary installer 新增独立 update-only 函数/入口，复用 verified_download、许可证/源码保留、installation_lock、command_version、publish_binary。与完整安装分开：不调用 install_verified，不创建/修改 config、selected、subscription、凭据、PATH、Shell文件，不调用 helper、sudo、launchctl、WebUI restart、VPN control。
- 只允许普通用户 macOS arm64/amd64 embedded core，target 必须是当前应用目录中的现存普通文件 anytls-macos 或历史 anytls；拒绝符号链接 app/target。具体目标由 CLI os.Executable + EvalSymlinks 决定，不接受 HTTP 任意路径。
- check 保留五字段 JSON，source_only 改为根据当前 Go 程序架构（runtime.GOARCH）的二进制及对应源码附件判断（且严格校验同 tag 官方 URL、唯一性）。源码归档和 SHA256SUMS 继续必需。没有当前架构完整预编译材料时仍可说明 source_only=true，但执行安装必须拒绝，不能回退 Go。
- latest 仅同版本体系严格递增；显式 CLI --version 保留人工回退。网页固定 checked stable version，不允许由HTTP传版本/URL/路径。
- 下载精确 tag 二进制、对应源码、应用源码和 SHA256SUMS，校验 HTTPS 来源/重定向、安全解包、完整 SHA、Mach-O、manifest 平台及 tag/commit。更新固定沿用当前 Go 程序架构，并传 --update-arch arm64/amd64 至可信Python；此参数仅update-only接受，不能改变完整安装原有硬件detect_arch政策。Rosetta amd64程序在Apple Silicon继续装amd64包（既有程序已可运行）；不自动跨架构。Python平台只核macOS及允许的进程/宿主兼容性，不再次重新选包。附件精确为 anytls-core-TAG-darwin-ARCH.tar.gz、anytls-core-TAG-source.tar.gz、SHA256SUMS、anytls-core-TAG-corresponding-source.tar.gz（arm64）或 anytls-core-TAG-darwin-amd64-corresponding-source.tar.gz（amd64）。任一已出现的必需附件重复或URL不符均拒绝；包/CCS缺失则source_only=true且禁止执行安装。
- 所有必要材料先复制保留到 app/releases 唯一目录并读回 SHA，再执行候选 version（独立超时）验证目标 tag。必须修改共享 publish_binary：复制旧程序时流式计算源SHA，close后独立读回备份SHA，完全相同才原子发布；读回失败/摘要不符绝不调用replace，同时回归原source/full installer，不弱化原保护。
- 发布后独立 version 验证，成功明确返回 UPDATED + restartRequired=true，磁盘程序与当前 WebUI 内存版本分开；本次不自动重启 WebUI或VPN。发布后验证失败属于 UPDATE_VERIFY_FAILED，不声称旧程序未变或自动回滚。
- 跨进程共用现有 app installation_lock，网页 actionMu 仍持有到子进程实际 Wait 与版本读回完毕。HTTP取消在安装接纳前可拒绝，接纳后同步等待不解绑；Go父CLI对唯一Python publisher保留独立35分钟context，超时kill并Wait后才返回；这是整体上限，不是Python自身或旧1800秒build timeout。另保留120秒网络read timeout与每次version子进程20秒期限，不额外增加Go/compiler进程。超时/崩溃不声称全局原子或回收任意后代。

## 受控失败

- 用固定类型/枚举，不匹配原始异常文本，不向网页回显 stderr/URL/文件内容。
- CLI update --check 失败和安装子进程失败需可由网页区分：检查失败 UPDATE_CHECK_FAILED，缺 Python UPDATE_PYTHON_REQUIRED，缺平台包 UPDATE_BINARY_UNAVAILABLE，下载 UPDATE_DOWNLOAD_FAILED，材料/校验 UPDATE_VALIDATION_FAILED，保留/备份/发布 UPDATE_PUBLISH_FAILED，替换后核验 UPDATE_VERIFY_FAILED。无可信分类保留 UPDATE_UNAVAILABLE。
- 协议由专用固定子进程 exit code 传递，且仅 update CLI 使用；不得改变其他命令退出契约。Python入口对各阶段异常映射固定码；新CLI将其包装 typed update error，main 对该类型返回相同固定码。网页检查/安装按已知 exit code 白名单映射HTTP JSON error，未知码不透传。错误提示说明具体阶段与已知文件状态边界，不统一保证旧程序不变。
- 固定退出码：40=UPDATE_CHECK_FAILED，41=UPDATE_PYTHON_REQUIRED，42=UPDATE_BINARY_UNAVAILABLE，43=UPDATE_DOWNLOAD_FAILED，44=UPDATE_VALIDATION_FAILED，45=UPDATE_PUBLISH_FAILED，46=UPDATE_VERIFY_FAILED，47=UPDATE_UNAVAILABLE。Python只允许42-47，CLI检查解析失败为40，LookPath缺Python为41，main仅errors.As到专用updateError时返回该白名单，其他命令仍exit1。网络打开/read抛异常为43，HTTP成功但hash/JSON/归档/manifest校验失败为44；先分类底层typed异常，不以原始文本分类。保留材料/备份/rename异常45，发布前候选version失败44，发布后version失败46（包括网页独立读回失败或与目标版本不符），父context超时47（状态待核对），unknown子exit（包括通用1/2、信号）47。HTTP只投影固定error码，不透传原始错误。
- 网页current始终为内存currentVersion()，新增installed为磁盘CLI报告/独立version核验值；检查响应中两者不同时restartRequired=true并status=RESTART_REQUIRED（若还有可安装新版本优先UPDATE_AVAILABLE，但restartRequired仍true）；本次安装成功响应仍用UPDATED，installed为核验到的目标版本且restartRequired=true。available取磁盘CLI检查结果。重复check、响应丢失或先前核验失败不能把磁盘新版冒称当前WebUI新版。没有磁盘身份时返回受控失败并清空旧成功，不猜测。UPDATE_VERIFY_FAILED/超时显示安装结果待核对，保留备份及材料，不自动回滚、不要求外部安装器；由代理独立核对installed version/SHA/backup后在独立授权下恢复。发布前/后version错误文字使用中性描述，不无条件声称旧文件保留。
- 前端覆盖所有新增错误提示；检查/执行更新开始前清除旧结果及可更新标志，失败不能保留旧 UPDATED 或可点击旧安装状态；成功显示已安装版本、需重启控制台且 VPN 未重载，不把未执行重启写成功。

## 验收

1. 同一新增回归在冻结旧版业务失败、新版成功（非编译失败）：预编译更新无需 Go/特权/配置写；缺包拒绝；typed失败穿过真实认证ServeHTTP和CLI子进程。
2. Python UNIT 使用真实临时文件和已存在 fixture，网络/候选执行标SIMULATED；覆盖材料复制/sha、备份/发布失败、无 helper/sudo/WebUI/配置副作用、双架构、旧名、symlink拒绝；全部 scripts tests + 两平台分支预检。
3. Go 更新元数据、错误投影、HTTP认证/Origin/CSRF、真实子进程取消/Wait/锁与版本核验。原生 Mac 全套/vet/build，遵守固定 wrapper、tags、Go1.26.8、隔离缓存及只计量资源（不恢复已取消容量门）。
4. 隔离 Mac appdir 用旧版本标识但同一更新实现，真实登录→check→POST update→官方 v2026-10-22-05预编译下载→版本/SHA/备份读回，证明不是mock；PATH排除Go，验证原私有配置/选择/凭据与正式VPN/助手/DNS/proxy未变。安装接纳后不触助手、不停止正式服务。另以真实浏览器验证按钮、失败码及成功反馈；synthetic API与真实HTTP分开。
5. 精确源码 SPEC→独立QUALITY复审后提交，clean-native最终版本、分支CI成功后新不可变标签；公开双架构附件与源码校验。旧Release不移动不覆盖。现装旧程序不可能靠网页自行改变已有更新器，首次修复部署由代理在获准范围内备份替换用户程序并切换WebUI，绝不要求用户跑安装脚本，不触VPN或root助手；切换前确保最终候选独立审查通过并核对保护状态，切换后真实登录检查API/资产/版本。若无部署授权则请求精确授权，不假称上线。
