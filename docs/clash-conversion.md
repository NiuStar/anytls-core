# Clash 配置自动转换与导出

## 产品契约

用户要求不再用一刀切安全解析门槛拒绝Clash YAML，识别后转换成本工具配置，并导出转换结果。本轮取消对anchor／alias／merge及任意path字段的整体拒绝，转为解释配置语义；仍保留基本格式有效性、HTTPS订阅公网访问、TLS证书验证和订阅凭据保护，不将取消格式门槛解释成读取任意本机文件或访问内网的授权。

Clash是配置格式，不是可改名成AnyTLS的传输协议。转换器不得将SS／VMess／Trojan等节点改type后冒充可用；应列出不能转换的节点类型和规则，阻止部分内容被静默应用。AnyTLS节点、手动选择组及可表示的规则转换为本工具nodes／proxy-groups／rules。自动测速或故障切换转为手动选择须明确列出语义变化并在应用前确认。

YAML模板展开应保留字符串与数字形密码的类型语义、显式字段覆盖及merge顺序；循环或无效结构属于格式错误，不是重启一刀切语法禁用。HTTP provider的path是缓存提示，不应当成本机文件读取目标；支持的provider内容拉取后内联，无法转换的格式逐项列出。只有实际依赖本机文件的字段需要用户明确提供资源，不能因为字段名叫path就拒绝整份订阅。

## 导出

- 预览响应增加conversion：来源格式、是否转换、warnings和issues。存在issues时无提交token，不伪装成功。
- POST `/api/v1/import/export` body `{token}`，If-Match和会话使用原预览绑定，返回 `{yaml,filename,format}`；不消费预览，不写文件、不重载VPN。
- GET `/api/v1/config/export` 为用户显式导出当前配置，返回本工具YAML，不包含私有订阅元数据或URL。
- 浏览器导出前明确提示文件含节点密码；仅本机Blob下载，不写localStorage，不输出配置到普通日志。
- 预览有转换差异时，提交需明确确认`accept_conversion:true`。TLS风险仍是只读说明，不恢复强制跳验勾选。

## 验收边界

实现、原生测试、独立审查和隔离HTTP／浏览器验证完成前不替换正式程序；不自动导入用户真实订阅、不重载现有VPN。当前文档是开发合同，不是已支持全Clash或已上线声明。
