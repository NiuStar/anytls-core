# R10 真实实现候选验收

## 设计与范围

已批准原型 r10-final HTML SHA256 `0647fa048f617db39d5f8c0992fc32d1fe070aa6716301e6f129a89aea87de56`。真实实现基线 `a0f6b489f5b71b5c69e68e7da1975009b5c3f859`，分支 `feat/r10-product`。原型示例数据未带入产品业务响应；候选不授权替换正式入口、安装助手、启动或重载现有 VPN。

实现16路由、认证与原保存链、稳定活动方案和完整切换快照CAS、订阅预览/独立导入/每小时常驻检查/候选确认/前版本恢复、有限真实HTTPS检查历史、绑定核心实例的只读TCP/UDP tracker payload计量。Flow/ICMP原始包不计入payload。缺失和旧helper均不可用，不回填零或使用旧值冒充当前。

## 最终本地统一执行

原始证据：`/workspace/anytls-r10-product-evidence-r2/final-local-r1/`。

- `full.log`：751顶层PASS、2459子测试PASS、11包PASS、10顶层SKIP、零FAIL；SHA256 `a7a839235b8460951aa67ded33c462fe35c116ef8c92d14ab94f0b857db74702`。
- `vet.log`：rc0；SHA256 `494048bad1c50fd85a3e245950a7481941490a733c76c1bc644bd8d811e37679`。
- `build.log`：rc0；SHA256 `28eac56f96f432258a7f177529e31473dec0c88bf4817aedb33195254c20a5b9`。
- Linux候选36057493 bytes，SHA256 `de6a302e0bc6bf275073b92577ad30ad4105f1a477fbb15b66b1e975177d689e`。不是macOS可执行文件。
- 各阶段唯一wrapper END rc0、cleanup=ok、root/module ZIP输入不变；执行前后源码摘要一致。此说明文件在统一执行后新增，只作证据索引；后继原生提交另绑定完整源码。
- 10项SKIP包括未授权WAN、未提供参考核心、macOS专用和显式opt-in；不是10项PASS。真实HTTP浏览器独立启用后执行，见下。

## 分层证据

- 真实Go ServeHTTP＋Chromium：`real-http-attempt5/results.json`，121检查、35截图、零脚本错误，每图正CJK字体命中；真实配置/方案持久化与下载。特权生命周期与订阅provider为测试替身，不证明正式VPN或外网订阅有效。前次固定220ms读回断言失败保留，改为等待实际读回完成后通过。
- 最终前端：`frontend/successor-final-r5`，248检查/53截图/53正CJK读回；既有Node77项及迁移debug路由的runtime/startup浏览器套件通过。标记SYNTHETIC_API_FRONTEND，不借作真实后端证据。
- 后端修复：`anytls-r10-product-review/backend-r2`，完整switch CAS、网络完成前权限复核、四目标marker回滚、订阅apply启动回执的真实router定向回归；保留旧HOLD/RED与mutation敏感性日志。
- 统计：metrics-r1/r3历史HOLD保留；metrics-r4修正回拨区间并集，M1单writer/有界Stop和M2fd-relative目录信任不变。
- 流量：traffic-r2历史HOLD保留；traffic-r3排除raw Flow、无溢出历史总和/嵌套rate/minute校验。真实SDK内存Port收到UDP/ICMP原始包，但不计payload；不改变dispatch。
- 最终受影响只读复核：`anytls-r10-product-review/final-affected-r1/REVIEW.md`，组件限定PASS，不代签native或生产。

## 运行与安全边界

- WebUI普通用户运行，保Host/Origin/会话/CSRF/ETag；默认0.0.0.0是产品既有策略，不意味HTTP加密。测试入口与正式入口必须分离。
- 当前安装的旧helper/core没有本次新计量协议，保持UNAVAILABLE。不得为展示流量擅自重启正式VPN；未来正式授权、新启动注册/manifest绑定及原生peer验证另行验收。
- HTTPS检查是WebUI系统路径到固定端点的离散观察，不证明选中节点、全部网站或全天SLA。流量是SDK可见TCP/UDP payload，不是网卡、wire或整机总量。
- 持久化IO不可中断，Stop共享1秒预算并明确超时；同步New/load没有故障文件系统墙钟上限。配置/方案原atomic writer不具备已验证的掉电durability；回读和回滚仅证明活进程行为。
- Linux组件和交叉编译不等于macOS原生。原生full/vet/build、独立预览认证/页面/精确PID清理在执行前均NOT_RUN；最终状态以独立原生回执为准。
- 手机observed流量截图视觉请求曾504，记录UNAVAILABLE而非PASS。其它已审截图的批准不替代该未完成像素门。
