# R10 方案/订阅后端验证

## 已实现
- 稳定活动ID（配置同目录 `active-profile`），方案独立三文件私有快照；编辑成功只同步确切活动ID，切回恢复；重命名/删除稳定关联，复制不复制自动更新所有权。旧profile JSON无link兼容，GET profiles旧精确projection保留；detail=1是产品新字段。
- URL预览与确认导入独立不激活方案；安全fetch、转换、严格配置验证均复用现有代码。CSRF绑定10分钟预览，名称碰撞拒绝。URL只私有0600记录，公开DTO只来源host。
- 手动和常驻服务worker真实检查：网络及转换不持action锁，完成重新捕获来源与完整目标；同URL进程内单任务、取消零提交、失败保旧。停机不虚构检查，启动只执行已到期任务一次。
- 非活动无人工修改可更新但不控制网络；当前/冲突/失效选择仅候选。apply绑定完整目标/候选版本，保留前版本，restore先建候选。旧选择按完整typed node及组解析路径身份保存，失效需显式新选择，不按同名猜测。活动应用只调用现有finishConfigSave一次。
- metrics worker三处接线已完成：字段、真正服务start/Stop、认证后metrics GET分派；HTTP正控/拒绝矩阵通过。

## 工具与实际执行
Linux Go实际路径 `/home/hermeswebui/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64/bin/go`。必须用 `python3 scripts/go-patched.py --go <上述路径>`，不能普通go test（未补ACK的根依赖编译失败）。环境 `GOTOOLCHAIN=local GOWORK=off GOFLAGS='' GOPROXY=off GOSUMDB=off GOMAXPROCS=2`；tags `with_gvisor,with_utls,with_upstream_cleanup_patch,embedded_core`，`-p 2`。所有构建临时路径遵守现有TMPDIR。

证据目录 `/home/hermeswebui/.hermes/cache/scratch/r10-backend-tests/`：
- `final-targeted.log`：`test -count 1 -timeout 120s -v -run 'TestR10|TestWebProfiles|TestR10Metrics' .`，24顶层PASS、100子测试PASS，根包0.348s；其中两个TestR10Metrics均PASS。
- `final-full2.log`：`test -count 1 -timeout 180s ./...`，rc0，根包121.431s，其余包PASS；此期间另worker并发新增traffic包，最后full已包含该包（当时无测试）。
- `final-vet2.log`：`vet ./...` rc0。
- `final-build.log`：`build -o <证据目录>/anytls-r10-candidate .` rc0。
- 候选二进制36002660 bytes，SHA256 `59894dfa816d2765911c93a5bb0c8064ecaacb2ccd82cc422c2b61bb11159389`。没有安装/执行服务命令。
- wrapper END均认证原module inputs与ZIP未变、ephemeral_cleanup=ok。

## 发现与修复
- 后台worker测试原本同时抢action锁，TryLock会合理跳过当前tick；改用fetch见证channel先等待真正后台网络，再核持久化，不以浏览器或单函数调用伪造后台。
- 首轮final-full该测试失败已保留 `final-full.log`；修复后full2通过。
- 第一轮vet在另一worker写traffic接线的中间态报undefined trafficFrame；文件齐备后vet2及build通过，不修改他人所有权文件。
- 初次普通go test触发4个小依赖下载并因ACK缺失失败；随后全部wrapper运行设置GOPROXY=off，未改依赖或全局cache源码。

## 未执行与边界
- race NOT_RUN（共享磁盘随后剩余约718MB，避免生成大型race缓存）；macOS原生R10候选 NOT_RUN；本worker未浏览器验收，由UI owner/父级完成。
- 未触SSH、正式helper/VPN、发布、真实私有配置；无commit；未人工删除workspace文件。两个已有core dump属于并行浏览器验收，未删除/读取内容。
- 共享树仍在并发开发；full2/vet2/build仅证明各执行时已落盘版本，不可当最终冻结SHA验收。父应在集成冻结后重跑。
