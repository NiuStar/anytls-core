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

实现已于本机正式部署为 `v2026-10-21-05`，产品提交 `c92c04a`，程序 SHA256 `5995a3350677587181c583e15e671284b1c97d870487660ab07cdc7fff5a2389`。Mac 原生全测244顶层／454子测试PASS、3SKIP，vet/build通过；Linux Chromium合成API验证真实下载字节、固定文件名、转换差异显示、输入失效、阻断与1440／390／360布局，JS错误0。

初轮独立审查FAIL三项保留：别名DAG展开、远程provider CA来源、当前导出差异丢失。父修复并在原生新增回归通过：按现有配置大小界限预计算DAG成本及有界编码、每个远程provider独立检查实际CA引用、导出携带report且前端显示warnings。此为父修复验收，未冒称后继独立复审通过。

正式18089实际登录与静态资产读回通过，WebUI PID25255；合成Clash模板在正式API预览并两次导出相同原生YAML，没有提交或重载。现有正式配置含SS节点，当前导出明确422列出不支持项，不静默丢弃；不能声称该混合配置已经成功转换。原配置、选择、密码SHA及VPN PID/program/runs/state、DNS/proxy摘要前后相同。旧程序与配置在Mac私有 `~/.anytls/backups/before-v2026-10-21-05`。GitHub公开二进制Release未更新，本机部署不等于完整Clash协议生态支持。
