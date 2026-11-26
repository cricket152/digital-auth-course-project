# 数字认证技术大作业

本仓库用于小组共同维护数字认证技术课程项目。选题、开发语言和运行方式将在小组确定后补充。

小组职责、联调顺序和提交材料见 [六人分工与交付安排](./分工与交付安排.md)。

## 组内协作

1. 取得仓库写入权限后，克隆仓库并从 `main` 创建自己的分支。
2. 在分支上提交改动并发起 Pull Request，说明改动及验证方式。
3. 合并前由组员审阅。合并后同步本地 `main`。

课程要求和原始报告模板见 [作业要求](./作业要求/)。密钥、证书、令牌和本地环境配置请保存在本地。

## 完整证书生命周期

需要 Node.js 24 和 PATH 内的 OpenSSL 3。

```powershell
npm ci
npm run app
```

打开 [本机课程应用](http://127.0.0.1:18446/)，按下面的顺序操作。

1. 打开「客户端与聊天」，在需要时点「添加客户端」。每个客户端注册独立普通账号，点击「生成 CSR」，核对申请详细信息，再点击「提交证书申请」。本机客户端代理生成并保管独立私钥，证书申请接收 PKCS#10 请求。
2. 从左侧打开「证书审批」并用 `admin` 登录。初始密码保存在 `.prototype/course-app/admin-password.txt`，启动终端也会列出路径。展开申请查看 CSR 和提交时间，再执行审批签发。客户端可下载签发的证书。
3. 从左侧返回「客户端与聊天」，让相关客户端分别点「持证连接」，从在线列表选定收件人再发送。登录管理员后，可在「认证记录」查看实际握手、证书绑定、接入和转发。
4. 管理员停用任意一张已签发的证书，该用户的本机聊天连接关闭。用「重连验证」可看到持停用证书接入被拒绝，再次申请会生成新的密钥和 CSR。
5. 从左侧打开「TLS 对照」，点「运行对照」。页面列出 CA 签发的单向 TLS、双向 TLS 缺客户端证书、自签名证书的默认信任与显式信任四种实测结果。

本机应用监听回环地址。启动终端也会打印同一界面的单向 HTTPS 地址。直连 HTTPS 时浏览器需信任 `.prototype/course-app/ca/ca.crt`。默认的本机 HTTP 页面供无需导入证书的演示使用，聊天代理到聊天服务的传输使用两个各自持证的 mTLS 连接。

账号、申请和签发状态存于本机 SQLite，CSR 草稿保存在独立的 `certificate-drafts.sqlite`。课程私钥和初始管理员密码留在 `.prototype/course-app/`。`npm test` 会使用隔离运行目录执行完整生命周期和 TLS 对照。

## 双向 TLS 网页原型

### 一页演示

运行下列命令，在浏览器打开 [本机演示页](http://127.0.0.1:18444/)。

```powershell
npm ci
npm run demo
```

演示服务启动时自动生成一组独立的测试证书，为 Alice 和 Bob 分别建立 mTLS 连接。页面打开后两端自动连上，可以从左右两栏收发消息，也可以用「验证无证书」查看握手拒绝、用「停用 Bob 并重连」查看服务器拒绝接入，随后恢复 Bob。

演示页仅监听本机，页面通过本机演示服务操作两个持证连接。测试私钥留在服务端临时目录内，浏览器无需导入证书。这组测试证书与独立原型的证书目录分开。端口可通过 `DEMO_PORT` 指定。

### 复核认证证据

网页下方的「认证过程与服务端证据」显示运行时记录。运行 `npm run demo` 的终端会同步输出 JSON 事件，网页可以下载最近 80 条 NDJSON 记录。

| 场景 | 在日志中查什么 |
| --- | --- |
| CA 签名校验 | `pki_signature` 中的签发者、序列号、SHA-256 指纹和签名验证结果 |
| 持证接入 | 按 `connection` 关联 `tls_established` 与 `websocket_admission`。前者记录 TLS 版本、密码套件及证书验证结果，后者记录证书绑定的账号和 HTTP 101 |
| 未持证接入 | `tls_rejected` 中的 OpenSSL 错误码 |
| 证书停用后重连 | 同一 `connection` 先出现授权通过的 `tls_established`，再出现 `certificate_revoked` 和 HTTP 403 |
| 发送消息 | `message_relayed` 记录发送方与接收方的两个连接编号、账号和 UTF-8 字节数 |

服务端通过受信 CA 验证客户端证书，应用查登记表确认账号及证书状态。聊天服务分别用两个 TLS 连接接收和转发消息。日志字段限定为认证、连接和转发元数据。

`npm test` 从命令行发起真实 TLS 和 WebSocket 连接，对照握手事件与接入结果。要独立验证下节生成的直连测试证书，可以运行 OpenSSL。

```powershell
openssl verify -purpose sslclient -CAfile .prototype/demo-pki/ca.crt .prototype/demo-pki/alice.crt .prototype/demo-pki/bob.crt
openssl verify -purpose sslserver -verify_ip 127.0.0.1 -CAfile .prototype/demo-pki/ca.crt .prototype/demo-pki/server.crt
```

### 直接用浏览器持证验证

原型验证浏览器持证接入、证书与账号绑定以及两人私聊。测试页与 `WSS` 共用一个启用 mTLS 的 HTTPS 入口。聊天服务器通过各客户端各自的 TLS 连接转发消息。

需要 Node.js 24 或更新版本，以及 PATH 中的 OpenSSL 3。

```powershell
npm ci
npm run pki:setup
npm run check
npm test
npm start
```

`pki:setup` 生成一套本地实验 CA、服务端证书、两个客户端证书和状态表，保存在 `.prototype/demo-pki/`。再次生成可用 `PROTOTYPE_PKI_DIR` 指定 `.prototype/` 下的新目录。

默认入口为 `https://127.0.0.1:8443/`。在专用测试环境中信任 `ca.crt`，并在两台测试客户端分别导入 `alice.p12` 和 `bob.p12`。证书包的导入密码为空。每台客户端只需要 CA 公共证书和自己的证书包。

在两台机器联调时，在服务器上先设置 `$env:PROTOTYPE_LAN_IP` 为本机局域网 IPv4，再运行 `npm run pki:setup` 和 `npm start`。使用新证书目录时，两个命令应使用相同的 `PROTOTYPE_PKI_DIR`。客户端通过服务器局域网 IP 访问。`PROTOTYPE_PORT` 可改端口。

测试停用时，在另一终端运行 `npm run pki:status -- bob revoked`，然后让 Bob 刷新页面或重新连接。服务器会在新接入时查询状态并拒绝。运行 `npm run pki:status -- bob active` 可恢复测试账号。

### 原型接口

- `GET /api/identity` 返回当前证书绑定的 `user`，停用时返回 HTTP `403` 和 `certificate_revoked`。
- `WSS /chat` 在接入时再次验证证书状态，成功后发送 `ready`。客户端发送 `{"type":"send","to":"bob","text":"你好"}`，接收端收到 `message`，发送端收到 `sent`。
- 服务器根据连接证书填写消息的 `from`。`invalid_message` 和 `peer_offline` 分别表示消息不合规和对方未连接。

正式注册登录、网页证书申请与审批、单向 TLS 对照和 Next.js 界面安排在后续迭代。
