# Chrome155 / Go1.27.3 候选最终验收

运行源码提交：`37c5dbc779ae952648a7c3c1446eef4fabf4a9c0`，分支 `feat/chrome155-go127`。这是候选，不是已发行 v2026-10-24-03；VERSION 暂未升号，包名沿用该值但只存放在隔离候选目录，不能上传覆盖旧发行附件。

## 已完成

- Go1.27.3；固定 refraction uTLS `v0.0.0-20261006195536-6ebdceb2607e`，旧 MetaCubeX 消费者保留。普通 AnyTLS 的默认／Chrome 实际调用新后端，显式 `golang` 仍是兼容回退。
- Mac Studio 干净 Git 副本原生完整回归：417 项主测试、1,122 项子测试通过，3 项跳过；`vet`、缺 uTLS 构建拒绝、arm64 构建、amd64 交叉构建、Python 工具及 wrapper 测试通过。与先前 v5 的419/1138不同，最终干净树不带三个独立辅助观测夹具，新增会话记录测试；分别保留原始日志，不能混用计数。
- 13 条验收命令全部返回0。原生执行仅 arm64；amd64 不以交叉构建冒充 Intel 原生业务运行。
- GitHub CI run `40083144172` 的 Linux、Mac arm64、Mac Intel 三项 success，源码 SHA 与运行提交一致。
- arm64 二进制 SHA-256 `ff15c99877cd153f22c72166ff97808ead14e13ffd48dbe31200eec6af75c533`；amd64 `266247ef496e4554564c15c782db2703cbda9f59081f84237b2e1e6a763c5034`。
- 两架构实际包、源码及 CCS 读回：校验和一致，Go 源码 VERSION=go1.27.3，应用和补丁字节匹配提交，36 个链接模块、每架构133份许可证材料，refraction 模块 ZIP／h1／LICENSE 收录。
- 最终 arm64 CLI 与 Chrome156.0.8078.47 同回环端点各三份样本：默认／chrome 的 cipher、扩展集合、versions、groups、signature algorithms、key-share形状、ALPN offers、Trust Anchors 八项 GREASE归一化字段一致；显式 Go 对照有差异。首 Hello 一致不等于完整浏览器等价。
- 最终 SHA 对正式公开 anytls-go v0.0.28 重跑九例：默认／Chrome／Go × 正确认证／错误SPKI／错误密码，全部通过；负例目标零连接／零载荷，进程全部wait、端口全部回收。首次lsof诊断超时的FAIL保留，独立v2诊断等待放宽后通过，未改业务断言。
- 最终二进制独立 WebUI 部署：回环随机端口、独立程序与配置、真实登录和会话读回、Origin／CSRF 拒绝、静态资源 SHA 通过，测试完进程／端口回收。
- TLS1.2与TLS1.3顺序连接、各49,152字节回显、真实记录类型／长度和服务器状态通过。当前未启用客户端会话缓存，两次连接 DidResume=false；只报告实测，不称恢复模式与Chrome一致。已有 AnyTLS 复用／idle／取消仍走全套真实回归。

## 授权边界

没有替换生产18089、安装／升级特权助手或断开／重连生产VPN；生产程序／配置／认证文件及当前进程／DNS／代理读回保持。没有发布新 tag 或覆盖旧公开附件。

## 原始失败

早期模块规范化、测试gofmt、SDK查询API和缺uTLS诊断错误均保留，修正后重冻复跑。最终归档审计首次用了含糊glob选中CCS，改为精确文件名后读回通过，未改归档。最终互通第一次在业务开始前遇到lsof属主诊断2秒超时，结果仍FAIL、资源回收成功；独立v2只调整诊断等待上界并复跑，业务认证／载荷断言未放宽。
