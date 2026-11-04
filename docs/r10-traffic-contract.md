# R10 VPN 字节流量契约

实现范围：`source=SDK_ROUTED_PAYLOAD` 仅为运行中 embedded Box 的 ROUTED TCP/UDP connection/packet tracker 可见 transport payload 字节；排除 ICMP 与所有 raw Flow 包（包括其 payload/IP/transport headers）。不是网卡、TLS/wire、全设备或被拒绝/DNS/早期失败总流量，不包含 TCP/IP headers 或 TCP 底层重传；tracker 自身再次读写的 payload 仍按实际读写累计。不得将记录条数当 bytes。

- 计量复用 sing 原生 `bufio.NewCounterConn/NewCounterPacketConn` 的 CountFunc，保留 unwrap/vectorised/batch/read-waiter 优化；RoutedFlow 返回 SDK 允许的 nil tracker，仅排除计量，不改变 Flow dispatch/路由能力。仅 atomic 饱和累计，不留目的地址或连接表，无 Clash/API/log/event manager 副作用。
- 仅 root registration + staged config + 编译 manifest 已验证的 `-record-service run` 开启；计量绑定 UID、config_identity、instance_id、generation、manifest_id、runtime_sha256；不读取旧配置重编译归因，不创建 HTTP root 服务，不安装 helper、不启动/重启 VPN。
- 累计与纳秒/字节差使用 canonical 十进制字符串；累计饱和锁存，不回绕。下载/上传分别为 tracker write/read（与 SDK trafficcontrol 定义相同）。二者逐个原子读取，不宣称跨方向事务一致。
- 5 秒采样；rate 为实际同实例单调时间 delta bytes / delta ns，首次/非运行/饱和为 null。分钟历史最多 1440 个实际完成区间，按实际单调跨度保留最多 24h；不跨实例相减、不补空缺、不制造零点。UTC 仅显示，不参与 rate 算法。
- 一个独立后台 reporter 负责采样及 fixed records namespace 文件安全持久化；吞吐回调无磁盘/锁/JSON/goroutine。磁盘错误只令 telemetry unavailable，不能改变 VPN 成败。持久化不恢复累计或伪造连续历史。
- helper 只读 `traffic.read`，请求固定 schema，不接受 UID、路径、配置内容。复用现有 Unix peer UID、socket 权限和 Web 登录/同源防护。递归拒绝重复、未知、缺失字段，限制 frame 大小，检查枚举、来源、绑定、单调历史与 canonical 数值。history 每段实际跨度至少 60s、允许 gaps；不相交 retained history 各方向之和不得超过累计（无 uint64 溢出），完全包含在某 history 段内的 rate delta 不得超过该段同方向 delta；无需 retained history 恰好等于累计。
- 读取用已注册 config_identity 推导固定 records namespace。必须同时证明当前 writer lock 被持有、latest/header/state 与 traffic 绑定一致、state 未关闭、traffic RUNNING 且心跳新鲜；latest 文件本身不证明 VPN 活着。不可读、旧 helper、失效/过期实例一律 UNAVAILABLE，不能把缓存展示为当前值。
- Web 接口由父 owner 将 `GET /api/v1/traffic` 路由到 `getTraffic`（完整鉴权 ServeHTTP 外层），再融合 metrics；`webui.go` / assets 不归本 worker 修改。提供 `controlHelperTrafficRequest` 供融合，不改 connectivity probe 组件。

验收分层：真实 loopback TCP/UDP exact payload、counter/关闭取消；真实 SDK 内存 UDP raw packet 与 ICMP Flow dispatch 仍成功且不计字节；有限历史/strict codec；安全 fixed-path 持久化与 Unix IPC 权限替身；真实认证 ServeHTTP（父路由接线后）。macOS 原生 peer 权限、已安装 helper 与正式 VPN 观测未在 Linux 代验。
