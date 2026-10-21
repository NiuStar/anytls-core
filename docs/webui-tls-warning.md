# WebUI TLS 跳验提示修订

基线 d960d77。用户明确要求将强制勾选改为只读风险提示，不再逐操作确认 TLS 跳验。

- 移除 `insecure-consent` checkbox，所有视图仍显示中间人攻击风险说明。
- WebUI start/reload 和保存自动应用传 `confirm_insecure:true`，stop 保持 false；含义是允许节点配置显式要求的 skip-cert-verify，而不是强制所有节点跳验。
- 未改后端配置编译、CA、SNI、节点 skip-cert-verify 值或系统权限。已有 CA 校验分支优先级不变；未配置跳验的节点不因此变为 insecure。CLI 终端确认不受本次网页修订影响。
- macOS 管理员授权仍由系统弹窗处理，网页不收系统密码。
- Browser+synthetic API 已验证无checkbox、风险文本、四类保存与start/stop参数，以及四入口×应用成功/失败后刷新失败仍保留结果，无JS错误和窄屏溢出；非真实TUN授权实测。
- Go源码完全未变，保留上一轮172顶层／386子测试PASS、3skip与vet证据；Mac原生重建嵌入资产成功。二进制SHA256 `f7701215c239d669d30a1f714b10d4dd2c23ca3778bff33535dbd2fc4bf8dfee`。
- 独立静态复核 `PASS_SCOPED_QUALITY`，两页面与后端策略SHA绑定通过；正式部署读回另存私有证据。本轮无新Release，VERSION保持v2026-10-21-02，不以版本字符串单独辨别修订，使用commit和SHA绑定。
