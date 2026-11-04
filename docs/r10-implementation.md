# R10 原型产品实现

## 授权与基线
用户已批准按 r10-final 原型开发系统。原型 `/workspace/anytls-user-product-design-r10-final/index.html` SHA256 `0647fa048f617db39d5f8c0992fc32d1fe070aa6716301e6f129a89aea87de56`。16 个路由，桌面1440、手机390。产品基线 a0f6b489f5b71b5c69e68e7da1975009b5c3f859，独立分支 feat/r10-product。

只开发、测试及隔离候选验收；不推送公开发行、不替换正式入口、不安装助手、不启动/停止/reload现有VPN、不删除用户文件。

## 实现合同
- 延续原型蓝白、208px侧栏、圆电源、手机44px点击区域、品牌版本与GitHub入口。真实登录；所有普通内容来自真实认证API，不保留原型示例业务数据和模拟完成逻辑。
- 首页区分作业运行和实际网络检查；缺流量/延迟/SLA历史标未记录，不能从路由记录计数推断流量或连通率。版本未检查不可绿标已是最新。
- 保留 Host/Origin/会话/CSRF/ETag、saved/applied区分、旧助手兼容、严格TLS、规则保序和最终MATCH保护。保留原API兼容。
- 16路由：overview、connections、nodes/list、nodes/groups、settings/general、settings/profiles、settings/import、settings/subscriptions、settings/rules、settings/advanced、settings/update、debug/versions、debug/dns、debug/operations、debug/logs、debug/report。
- 方案：稳定ID、独立三文件快照；共享节点页方案选择器；切回恢复编辑而非只改名称；重命名不丢订阅；复制和删除只操作显式方案，不影响活动网络。
- 订阅：预览后导入新独立方案，名称碰撞拒绝，不激活；常驻WebUI服务每小时检查，浏览器关闭仍运行，进程停止期间不虚构检查。网络抓取复用安全边界。按源更新目标方案；失败保留旧数据；非活动无冲突可更新但不切网络；当前或人工冲突仅候选待确认。确认绑定目标与候选完整版本，保留前版本，失效选择不按同名猜测。脱敏来源不输出路径/查询令牌；同源单任务；取消不提交。
- 节点/组/规则/导入/原始YAML/更新用真实既有保存链，不由浏览器另发reload；原始敏感配置仅显式打开；诊断报告用白名单，不混入订阅令牌/原始配置。

## 验证
每个新增后端端点须完整认证 ServeHTTP 合法正控和拒绝矩阵，真实文件持久化、冲突和零服务副作用；前端实际 Chromium16路由双宽、真实下载/确认/取消/迟到所有权。定向Go→full/vet/build、独立代码审查和当前像素复核。真实监听HTTP与模拟权限分列。macOS原生与正式助手/TUN保持独立门。全部未执行项写NOT_RUN，不以原型测试数字当产品验证。
