# 安装进度与网络等待提示

用户报告公开一键安装命令长时间没有输出。只读核对当次Mac进程：已经进入可信Python安装器，先取得SHA256SUMS，再下载官方binary；文件从0增长到1MiB，约4分钟仍在下载，不是等待系统密码。后继观察进程已退出，未获得该次终端退出码，不能声称重装成功。没有为诊断另起完整安装、终止旧安装或操作VPN。

## 改动

- bootstrap shell在每个可信组件下载前后立即写阶段信息到stderr，curl使用进度条；原有HTTPS／连接和总超时不变。
- Python安装器6阶段提示：官方版本和附件、安全解压及身份、材料保留、系统助手授权、旧程序备份替换、WebUI切换。
- 网络请求打开或read阻塞时每约5秒输出心跳；显示实际交付读取循环的字节、服务器提供时的Content-Length与耗时。不伪造百分比或剩余时间，也不把暂未获得完整读取块解释成网络零传输。
- 所有进度stderr及时flush，检查模式stdout继续只有最终JSON。只显示原请求的安全basename，不显示签名重定向查询／认证资料。
- 传输结束的“完成”不等于SHA通过；所有归档校验成功后才进入第2阶段。失败／取消标记且回收心跳线程，不打印系统密码。
- 网络超时和信任／校验／安装顺序、WebUI切换、VPN不重启策略不变。旧已运行脚本不动态加载更新，不应并发重跑安装。

## 验证

- 原缺进度API的测试出现AttributeError，属于未实现API失败，不冒称业务RED。
- binary installer49项UNIT、source24项、package6项回归通过；Mac Python3.9运行49项UNIT通过。
- 真实Mac HTTP探针发现显式传HTTPResponse.read(-1)的兼容问题，改为默认read不传size并补回归；后继真实SHA256SUMS下载、实际摘要及开始／完成提示验证通过。原失败保留会话。
- 当前主机实际运行官方Release03完整check-download成功，stderr包含附件名／大小／5秒心跳，stdout JSON独立、download_verified=true、executed=false；没有再次执行用户系统授权或重启WebUI／VPN。

独立审查和公开main读回结果另随本次提交确认；本文不把下载体验改动声称网络速度修复。
