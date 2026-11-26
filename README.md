# 数字认证技术大作业

本仓库维护数字认证技术课程项目。课程应用使用 Node.js / TypeScript 实现客户端证书签发、双向 TLS 认证和在线私聊。

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

打开 [本机课程应用](http://127.0.0.1:18446/#start)，点击「开始实验」。Chrome 或 Edge 可以从同一页面操作至少两个客户端。

1. 为两个客户端注册独立账号，分别点击「生成 CSR」。展开「查看申请与证书信息」，核对申请主体、公钥算法和长度、签名算法及签名校验结果。可展开公钥的 PEM、签名十六进制值和原始 PKCS#10，再点击「提交证书申请」。
2. 从左侧打开「证书审批」并用管理员密码登录。初始密码保存在 `.prototype/course-app/admin-password.txt`，启动终端会列出路径。展开申请核对 CSR 后签发。回到客户端，检查证书由实验 CA 签发、用途为 TLS 客户端认证、CSR 与证书的公钥一致。可下载签发证书。
3. 让两个客户端分别点击「持证连接」，选择收件人并发送，再从另一端回复。客户端代理各自持证与聊天服务建立 WSS 连接，由服务端校验证书、核对账号并转发。
4. 在「TLS 对照」点击「运行对照」，查看单向 TLS、双向 TLS 缺客户端证书、自签名证书的默认信任与显式信任四个实测结果。
5. 管理员停用其中一张证书，确认该客户端离线。点击「重连验证」，会看到聊天服务拒绝旧证书的 HTTP 403。该账号重新生成 CSR、提交并获签后，用新证书上线并继续发送消息。展开「已停用证书」，选择对应序列号再次验证旧证书，确认旧证书依然被拒绝。
6. 登录管理员后打开「认证记录」。按账号、申请编号、证书指纹或 `#连接编号` 筛选，展开原始日志，或下载筛选结果为 NDJSON。网页保留本次服务运行的最近 80 条事件。

| 想说明的原理 | 可核对的记录 |
| --- | --- |
| 签发证书对应提交的 CSR | CSR 验签通过，CSR 与证书的 SPKI SHA-256 摘要相同，证书的 CA 签名校验通过 |
| 持证后接入并由服务器定向转发 | 申请编号出现在 `certificate_issued`、`tls_established`、`websocket_admission` 和 `message_relayed` 中。转发记录也包含接收端连接和申请编号 |
| 缺证与停用触发不同层的拒绝 | 缺证出现 `tls_rejected`。停用证书在仍有效且受信任时可以完成 TLS 握手，随后同一连接的接入记录为 `certificate_revoked` 和 HTTP 403 |
| 换证为何可以恢复 | 同账号的新申请、序列号和证书指纹与旧证书不同。新证书接入为 HTTP 101，旧证书的独立验证仍为 HTTP 403 |

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

注册、证书申请与审批、单向 TLS 对照请使用上方的「完整证书生命周期」入口。
