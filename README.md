# socks5-go

Go 移植自 [j-jiang/socks5](https://gitee.com/j-jiang/socks5/tree/5bef5d788b1f424f53359b130b707a621bc29c84)，上游提交 5bef5d7，Apache-2.0。保留 Java 版的 TCP 隧道协议、配置键、分流和监控格式。程序只用 Go 标准库，不需要 JVM 或外部 OpenSSL 动态库。一个二进制通过 client/server 子命令选择角色。

## 首次部署：三条命令

适用全新的 Linux amd64 / arm64 服务器（systemd、curl、OpenSSL 1.1.1+、Python 3，使用 root 终端）。已有安装不会被覆盖。

1. 在中心 **C** 的 root 终端执行：

   ```bash
   curl -fsSL https://raw.githubusercontent.com/Toby1GO/stest-relay/v1.0.0/install/center.sh | bash
   ```

   脚本自动识别公网 IPv4，生成 HTTPS 证书、管理员密码和 systemd 服务，打印面板地址和证书指纹。若机器的出口 IP 和公网入口不同，在命令末尾改用 `bash -s -- 你的中心公网IPv4`。浏览器首次访问时按安装输出核对自签证书指纹。

2. 登录面板，点击 **「安装一对节点」**，填写 server、client 的标识和公网 IPv4。先把 **server 命令**复制到 B 运行，看到安装成功后，再把 **client 命令**复制到 A 运行。命令使用独立的短期凭据，2 小时后或首次成功上线后失效。命令丢失且还没安装时，在面板删除未使用的节点对再创建。不要把安装命令公开。
3. 在「全部节点」确认两台在线，到「转发规则」选 A，添加第一条映射。B 在本机生成私钥，只上传公钥证书到 C，A 自动取得对应证书。每对有独立隧道 Token；按端口计量已开启。C 使用 /opt/stest-center，A、B 分别使用 /opt/stest-client 和 /opt/stest-server。服务名为 stest-center、stest-agent、stest-exit。
4. 云安全组需允许 A/B 和管理员访问 C 的 TCP 8443；允许 A 访问 B 的 TCP 8001；客户能访问 A 选定的 TCP 映射端口以及 UDP 20000–20127。需要面板测延迟时允许 C 访问对应 A/B 的探测端口。脚本不修改云安全组。

旧版中心手动升级到支持快速安装的版本后，需给服务设置 `STEST_PUBLIC_URL=https://中心地址:8443`，并用含该 IP/域名 SAN 的证书启动。启动参数、已有节点及手动接入仍兼容。

## A、B 两台服务器

普通代理模式：多台 PC → A（代理入口）→ TLS → B（出口）→ 目标。PC 通过 SOCKS5、HTTP 或 HTTP CONNECT 告诉 A 目标地址。先拦截、再匹配直连，其余经 B。直连由 A 发起，绕过 B。普通代理入口只支持 TCP；下面的固定落地映射可以按端口启用 SOCKS5 UDP。

1. 从 bin 选对应系统的文件，分别复制到 A、B。Linux amd64 和 arm64 二进制均可改名为 socks5-go，然后执行 `chmod +x socks5-go`。
2. 两端各复制 template-proxy.properties 为 proxy.properties。将 A 的 client.auth.token 与 B 的 server.auth.token.list 中某一项改为同一个随机值。模板沿用上游示例，两者最初不匹配。配置解析与原版一样，两端配置都要包含这两个键；B 的列表可以有多个 Token。
3. B 保管 TLS 私钥 server.key（PEM）和证书 server.crt；A 只需要证书。默认文件路径相对于**进程的工作目录**。可以复用原版证书。用私有 CA 时，A 配置 CA，B 提供带完整中间链且 SAN 匹配 server.host 的服务器证书。直接配置叶证书时支持原版使用的无 SAN 自签证书，仍校验证书有效期并要求证书匹配。
4. 在 A 设置 server.host 为 B 可达的域名或 IP；两端 server.port 一致（模板 8001）。只开放要用的入口：例如只用 SOCKS5，就在 A 禁用 client.http.enabled 和 client.https.enabled。A 的入口按上游行为监听所有网卡。用安全组限制 A 的来源为自己的设备或私网，B 的隧道端口只允许 A；A 的明文 SOCKS5 口令不能给 PC→A 加密。
5. 从配置目录启动。Windows 用 `.\socks5-go.exe server`（B）、`.\socks5-go.exe client`（A）。Linux 用 `./socks5-go server` 或 `./socks5-go client`。指定配置示例：`./socks5-go client -config /etc/socks5/proxy.properties`。也支持在最后追加 socks5、http、https 单独启用一个入口。
6. 在 PC 上将 SOCKS5 代理设置为 A 的 IP 和 9090；DNS 需要交给代理时启用远程 DNS。模板的 HTTP 代理端口为 9091，CONNECT 专用端口为 9092；二者均使用 http:// 连接代理。访问 HTTPS 网站时，浏览器到网站的 TLS 独立于 A→B 的 TLS。

## 按 A 的端口选择落地 SOCKS5

例如 PC → 广州 A → TLS → 香港 B → 台湾或日本 SOCKS5 → 网站。只升级 A 即可；B 可继续使用原 Java 或 Go 服务端。B 需要能访问对应落地，且落地允许 B 的出口 IP。

先按上面第 1–4 步配好证书和隧道 Token。在 A 的 proxy.properties 中添加映射（域名和目标端口请换成真实值）：

```properties
client.forward.11001=tw-node.example:1080
client.forward.11002=jp-node.example:1080
```

运行 `./socks5-go client -config proxy.properties forward`，只启用映射入口；B 仍运行原来的 server。确保 A 的防火墙允许客户访问这两个 TCP 端口。A 接到连接后，通过 TLS 要求 B 连接固定节点，然后双向复制字节。固定映射不使用普通代理的分流规则；B 不通时直接失败，不回退为广州直连。普通 client 启动方式则会同时启用已配置的映射和已启用的代理入口。映射变更后重启 A 生效。

| PC 的代理类型、服务器、端口 | PC 填的凭据 | 最终出口 |
|---|---|---|
| SOCKS5，广州 A，11001 | 台湾节点的账号和密码 | 台湾节点 |
| SOCKS5，广州 A，11002 | 日本节点的账号和密码 | 日本节点 |

账号密码由落地验证，A/B 都不配置落地凭据；A/B 之间的 Token 独立。TLS 仅保护 A→B 段。

### 两台 PC 共用台湾节点，以及如何启用 UDP

两台 PC 都可填写 SOCKS5、A 的 IP、端口 11001，各自建立连接，使用同一个台湾落地。如果使用同一个账号，能否多设备同时在线、并发数和带宽额度由节点服务商决定。

要让这个端口同时支持 TCP 和 UDP，A 和 B 都换成新版 Go 二进制，在 **A** 配置：

```properties
client.forward.11001=tw-node.example:1080
client.forward-udp.11001=true
client.udp.ports=20000-20127
# 若 A 位于 NAT 后，填 PC 能访问的 A 的 IP，UDP 端口须按原端口映射
# client.udp.advertise-ip=203.0.113.10
```

重启 A、B。PC 仍只填 11001；防火墙允许两台 PC 访问 A 的 **TCP 11001** 和 **UDP 20000–20127**。A 给每个 UDP 会话分配一个端口，范围满时拒绝新会话。会话只接受对应客户端 IP 和源端口的数据，TCP 控制连接断开后释放端口。若 PC 在 NAT 后且不知道对外 UDP 端口，其 SOCKS5 客户端应在关联请求中填写全零端点。

B 仍只需对 A 开放原来的 TCP 隧道端口，但须允许 B 向台湾节点协商返回的 UDP 地址和端口发包并接收回包。A→B 的 UDP 数据报封装在 TLS/TCP 中，所以这段丢包时可能有重传延迟。PC 软件和落地都必须支持 SOCKS5 UDP ASSOCIATE；开启的映射支持无认证或用户名密码认证、CONNECT 和未分片的 UDP 数据报。未开启的映射继续透明转发 TCP，兼容旧 B。

## 规则与监控

### 中心 WebUI：多台 A 的映射热更新

中心使用独立的 Go + Vue 程序 `stest-center`（构建：`go build -o stest-center ./cmd/stest-center`）。A 和 B 使用 `socks5-go`。中心可独立部署，游戏流量不经过中心。已有支持 UDP 的 B 不需要升级。首次将 A 的旧进程换成新版需要一次重启，请避开正在进行的对局；之后发布映射不需要重启。

1. **启动中心。** 在中心服务器准备管理域名和对应 HTTPS 证书。下面是 Linux Bash 示例，输入的密码至少 12 字节。状态文件的父目录须已存在并可写。一次只运行一个中心进程操作同一状态文件。

   ```bash
   read -rs -p '中心管理员密码: ' SOCKS_CENTER_PASSWORD; echo
   export SOCKS_CENTER_PASSWORD
   ./stest-center -listen :8443 -cert /path/to/fullchain.pem -key /path/to/privkey.pem -state ./center-state.json
   ```

   打开 `https://你的管理域名:8443/`，用户名 `admin`。本机试用可省略所有参数，默认 `http://127.0.0.1:8088/`。Windows PowerShell 可用 `$env:SOCKS_CENTER_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host -AsSecureString '中心管理员密码')).Password`，再运行 `.\stest-center.exe`。使用 HTTPS 反向代理时可保留回环监听，代理需转发 Authorization 请求头；远程 A 的 center.url 要指向公开的 HTTPS 域名。A 使用操作系统信任的 CA 校验证书。

2. **登记 A。** 网页点“接入 A 节点”，为每台机器填写不同的标识和区域。将页面生成的 `center.url`、`center.node-id`、`center.node-token` 三行加入 A 当前实际使用的 properties 文件，保留原有 B、隧道、映射和 UDP 通告 IP 设置。每台 A 使用自己的密钥，不要复用 B 的隧道 Token。在 A 上按原来的方式启动新版，例如：

   ```bash
   ./socks5-go client -config /etc/socks5/proxy.properties forward
   ```

   普通 client 模式也会同步映射；单独启动 socks5/http/https 入口不会。A 首次上线，页面自动导入已有映射、UDP 端口范围和通告 IP，不会以下发空规则覆盖它们。

3. **发布映射。** 在网页选择对应 A，增删改入口端口、目标或 UDP 设置，点“发布配置”。A 每 15 秒主动联系中心，成功后页面显示“已生效”；约 50 秒无心跳显示离线。端口冲突或缓存写入失败时，整批保留旧配置并回报错误，下次轮询会重试。这一状态确认的是 A 完成监听配置，不代表已经检测过目标节点连通性。页面保留每台 A 最近 40 条记录。

   同端口改目标或切换 UDP，只改变后续新连接；删除端口只停止接收新连接。已有 TCP 和已建立的 SOCKS5 UDP 会话继续使用原目标和原设置，直到客户端自己断开。中心暂时离线不会打断转发。

4. **持久化。** 中心状态默认保存在工作目录的 `center-state.json`。A 最近一次成功配置默认保存在工作目录的 `center-节点标识-applied.json`，可用 `center.cache` 指定绝对路径（父目录要可写）。重启 A 时优先恢复这个缓存，中心离线也可启动。接入后请从页面修改映射；properties 仍控制 B 地址、证书和隧道 Token。要退回独立模式，删除 A 的 `center.url` 并重启，将再次使用 properties 中的映射。请备份状态文件，并将服务工作目录保持固定。

- client.block.path（默认 ./block.conf）：每行一个域名，匹配该域及其子域；兼容 address=/example.org/0.0.0.0。
- client.direct.allow.path（默认 ./direct-allow.conf）：精确、前缀 abc*、后缀 *abc、包含 *abc*。两种文件均忽略大小写、空行和以 # 开头的行，约一秒检查一次变更，删除文件会清空对应规则。
- server.monitor.host 和 server.monitor.port 控制监控监听，默认 127.0.0.1:18080。GET / 返回 global 和 tokens 的流量统计。接口按上游格式返回 Token，请保留在受信管理网络。
- 正常退出（Ctrl+C，Linux 也支持 SIGTERM）后写入 server.stats.path（默认 ./stats.json）。下次启动可直接读取 Java 版统计文件。强制结束进程不会触发保存。
- 模板端口与不写配置时的内置默认值不同：省略时隧道为 58001；SOCKS5、HTTP、CONNECT 分别为 58080、58081、58082，只有 SOCKS5 默认启用。

## 编译与测试

Go 1.22+，无第三方模块。项目目录内执行：

```sh
go build -trimpath -ldflags="-s -w" -o socks5-go .
go test ./...
go vet ./...
```

只为本机测试生成一天有效的密钥和证书（在空目录运行生成器，拒绝覆盖）：先 `go build -o testcert ./cmd/testcert`，然后在测试目录运行生成的 testcert。Windows 命名为 testcert.exe。

端到端测试需要 Python 3 和 OpenSSL 或上述 testcert，可加原版 Java 可执行 jar 做混合部署测试：

```sh
python tests/interop.py --go-bin ./socks5-go --testcert ./testcert --java-client /path/to/client-1.0.1-jar-with-dependencies.jar --java-server /path/to/server-1.0.1-jar-with-dependencies.jar
```

测试在本机创建临时证书，向回环地址的 HTTP 回显服务并发送请求，覆盖密码认证的 SOCKS5、HTTP POST 和 CONNECT，通过全量字节比对判断成功。只测 Go 时省略两个 jar 参数。可指定 --java；--scratch 指向一个**尚不存在**的诊断目录以保留日志。

## 与 Java 实现的边界

固定映射启用 UDP 后使用 Go 扩展消息 7，协商成功后传递 SOCKS5 握手；CONNECT 传输字节流，UDP 则以一帧一个数据报传输。下面的协议兼容性说明针对原有 TCP 模式。

隧道仍是一条应用 TCP 连接对应一条 TLS 连接；大端 4 字节长度（含类型、不含长度字段）、1 字节类型、数据。保留原协议 1–6 的消息编号、认证/连接顺序及整连接关闭语义。Go 使用 crypto/tls（最低 TLS 1.2），密码套件由 Go 与对端协商，不复制原版 OpenSSL 的 TLS 指纹。控制帧上限 65535 字节，建连有超时；普通 HTTP 请求体上限 16 MiB，与原版一致。Go HTTP 栈会规范化报文头，不保证与 Netty 逐字节相同。日志不输出认证 Token。运行时、异常文本、构建方式与上游不同。

本次 Windows x64 回环测试：Go/Go、Java 客户端/Go 服务端、Go 客户端/Java 服务端均成功。每组四个并发请求、每个 180000 字节双向回显。一次请求结束后的 Windows 进程工作集：Go 客户端约 12–14 MiB、Go 服务端约 14 MiB，Java 客户端约 124 MiB、Java 服务端约 142 MiB（Java 使用 -XX:ActiveProcessorCount=2）。这是一次短时采样，不是堆大小、峰值内存或公网性能承诺。Linux 文件为交叉编译产物。

### 映射授权和节点退役

控制台按 A 和入口端口管理禁用、到期和续期。编辑后发布配置，在线 A 在下次同步时执行。已下发的到期时间缓存在 A，本地计时，重启或中心暂时离线时仍生效。日期按浏览器本地时间输入并转换为 UTC。普通移除映射允许旧连接自然结束，禁用和到期会主动关闭该端口的现有会话。取消禁用并将到期时间延后或清空即可恢复。
节点详情底部可以删除节点，需输入完整节点标识确认。中心立即撤销该节点密钥；支持端口策略的 A 在下次联系中心收到 401 时停用所有受管映射。离线期间尚未收到的变更无法立即执行。再次使用该标识需重新登记并配置新接入密钥。
A 的所有固定映射共用本机 client.auth.token，B 的 server.auth.token.list 是允许接入的隧道凭据列表。中心接入密钥和落地 SOCKS5 用户名密码各自独立。


### 出口监控与映射账单

在控制台登记 B 节点，将生成的中心地址、节点标识和接入密钥写入 B 的配置。B 必须信任中心的 HTTPS 证书。为每台 A 分配独立隧道 Token，在 B 的 server.auth.token.list 中允许它，再配置 server.meter.owner.<A节点标识>=该Token。在 A 配置对应 client.auth.token 和 client.meter.enabled=true。先升级 B 再启用 A 的计量。中心接入密钥独立于隧道 Token。

B 按北京时间自然月、A 标识和入口端口累计转发数据，保存在 server.meter.path（默认 meter-monthly.json），每 15 秒落盘并向 C 上报。异常掉电可能损失最后一个未落盘周期。C 的账本保存在中心状态文件旁的 .billing 文件中，与 B 的计量文件一并备份。重新使用同一个 A 标识与端口会延续该月账目。历史共享 Token 的总流量无法回填到各条映射。

在「用量账单」选择月份。按映射设置当月人民币单价，支持两位小数；整月费用为（上行字节 + 下行字节）÷ 2³⁰ × 单价，四舍五入到分。未定价的行继续累计用量，修改当月单价会重算整月。TCP 按转发字节计量，SOCKS5 UDP 包含数据报的 SOCKS5 头，不含 A→B 的 TLS 开销。

「网络总览」分别展示心跳在线状态和 C 主动发起的 TCP 建连耗时。C 探测节点上报连接的来源 IP，A 使用第一条启用的入口，B 使用隧道端口。探测依据当前部署的直连 HTTPS 拓扑，反向代理、NAT 或只允许 A 访问 B 的防火墙可能导致探测无结果。
