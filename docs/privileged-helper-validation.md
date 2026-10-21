# 助手首轮执行与审查

本轮未安装 root LaunchDaemon，未更换正式程序、WebUI 或停止 VPN。

## 原生执行

- 在 Mac 使用固定 Go 1.26.8、认证 wrapper、完整 embedded/gVisor/uTLS tags。
- 初次IPC测试临时socket目录过长，macOS sockaddr_un拒绝绑定，保留失败。改为短测试目录并由t.Cleanup回收，不改变产品socket路径。
- 后继全量：200顶层PASS、411子测试PASS、3顶层SKIP；targeted/test/vet/build rc=0。
- 额外实际Darwin LOCAL_PEERCRED UID与plutil -lint均PASS，不外推root对端或真实launchd安装。
- 首候选binary SHA256 `e521f9e4bd65efa161593bdc5d10054fd8d5f80ed4bac2242c60ccc7400656f5`；不会安装此后已变更的旧候选。

## 独立审查FAIL与后继修订

1. CH-SEC-01：固定注册配置与本地WebUI编辑配置缺少绑定，普通安装迁移可导致错报APPLIED。修订将认证响应绑定canonical配置路径SHA，动作前后核对，拒绝不同配置，不向IPC加入请求路径。
2. CH-SEC-02：仅bootstrap/print成功不能证明助手就绪，后续普通用户验收失败已出事务无法回退。修订将在root事务内验证running/PID与降权普通UID socket status+SHA后才提交，失败先卸载候选再恢复旧助手。

修复已完成，后继Mac原生定向／全量／vet／build全部rc=0：210顶层PASS、427子测试PASS、3顶层SKIP，包含真实内核peer UID与原生plist门。最终binary SHA256 `a4cd5da67587e44536a5e94d6860bf36abcb2217b484b2c825e1d9ed7f5c93d2`。父独立读回源码、日志与产物一致。

隔离真实WebUI完成登录、未安装助手明确HELPER_UNAVAILABLE、配置落盘读回、saved=true/applied=false、pending保留。未发送服务动作。测试进程已回收；首次收尾bind未设SO_REUSEADDR受TIME_WAIT影响，后继独立lsof无LISTEN及SO_REUSEADDR绑定通过，不重放保存。

最终v2独立复审PASS，随后部署前实际读取Mac发现/private/var/run为0775会被严格祖先校验拒绝。v3将socket移动到助手root保护目录run/，未放宽权限，并修正并发重新注册场景下不能保证“未操作VPN”的提示。v3原生211顶层PASS、427子测试PASS、3SKIP，vet/build rc=0；SHA256 `2e92864e83902517d8dfbc41973dac04c1c4ce15a930a93803c4822cd7e7c378`，源码、日志与产物已独立读回。

受控候选与一键本机安装脚本已放入用户.anytls目录，仅执行bash -n及--check，未安装root助手，未替换正式程序。脚本先一次授权安装并认证读回助手，再备份替换用户CLI和重启WebUI，不主动重载VPN；用户首次root安装与真实自动应用仍待验收。v3权限差异复审已通过 `PASS_SCOPED_QUALITY`，原审查与失败记录保留。

原失败和首轮结果不覆写，不将准备安装冒称正式部署。
