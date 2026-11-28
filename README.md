# 数字认证技术大作业

本仓库维护数字认证技术课程项目。课程应用使用 Node.js / TypeScript 实现客户端证书签发、双向 TLS 认证、双人会话密钥协商和加密私聊。

小组职责、联调顺序和提交材料见 [六人分工与交付安排](./分工与交付安排.md)。

## 当前进度与课程要求

**本机功能集成已完成，进入课程交付准备。** 默认演示在一台 Windows 电脑上启动独立服务端、Alice 和 Bob 三个进程，操作在各自的浏览器页面完成。小组已实测网页流程。可按[单机验收步骤](#单机独立服务端与双客户端)启动和复现。

| 课件第 6 页要求 | 当前落实情况 |
| --- | --- |
| a、b 开发环境与证书 | Node.js 24、OpenSSL 3。可生成实验 CA、服务端和客户端证书，并演示自签名证书的信任行为 |
| c CA 签发和在线验证 | 客户端在本地生成私钥与 CSR，管理员审批签发。支持管理员在线查验 CA 签名、有效期和登记状态，并验证停用后拒绝重连 |
| d C/S 聊天、客户机与服务器分离 | 已实现服务端与两个客户端独立进程。完整版通过回环地址完成本机演示，跨机器部署待联调 |
| e 两用户会话密钥协商和加密通信 | 已验证两端协商记录一致、双向 AES-256-GCM 加密收发和篡改拒收 |
| f 注册登录及单向、双向认证 | 原课设网页提供注册登录和 TLS 对照，独立客户端网页提供申请、持证连接和加密聊天 |

课件第 6 页用「可以支持」列出客户端 APP 和手机端 APP，第 10 页再次列出这两种形态。**手机端是否为本组选题的必交项，需由指导老师确认。** 当前有适配窄屏的客户端网页，独立进程绑定本机回环地址，尚未在手机真机上联调。若老师要求手机端，再确认手机浏览器能否验收，以及是否须提交 Android 或 iOS 安装包。依据见[课程课件](./作业要求/数字认证实验2026.pdf)。

下一步准备源程序、可执行程序、模板报告、PPT 和功能录屏。分机验证按指导老师确认的验收口径安排。当前验收状态见 [PROJECT_STATUS.md](./PROJECT_STATUS.md)。

## 组内协作

1. 取得仓库写入权限后，克隆仓库并从 `main` 创建自己的分支。
2. 在分支上提交改动并发起 Pull Request，说明改动及验证方式。
3. 合并前由组员审阅。合并后同步本地 `main`。

课程要求和原始报告模板见 [作业要求](./作业要求/)。密钥、证书、令牌和本地环境配置请保存在本地。

## 完整证书生命周期

需要 Node.js 24 和 PATH 内的 OpenSSL 3。要演示服务端与客户端独立运行，请使用下文的[独立客户端流程](#单机独立服务端与双客户端)。

```powershell
npm ci
npm run demo
```

`npm run app` 也可启动课程应用。打开 [本机课程应用](http://127.0.0.1:18446/#start)，点击「开始实验」。从左侧选择或添加客户端，每个客户端在主区独立显示。登录前，侧栏用「客户端 1」这样的编号标识，登录后显示用户名。切换侧栏条目时，原客户端继续在线接收消息。

1. 为两个客户端注册独立账号，分别点击「生成 CSR」。展开「查看申请与证书信息」，核对申请主体、公钥算法和长度、签名算法及签名校验结果。可展开公钥的 PEM、签名十六进制值和原始 PKCS#10，再点击「提交证书申请」。
2. 从左侧打开「证书审批」并用管理员密码登录。初始密码保存在 `.prototype/course-app/admin-password.txt`，启动终端会列出路径。展开申请核对 CSR 后签发。回到客户端，检查证书由实验 CA 签发、用途为 TLS 客户端认证、CSR 与证书的公钥一致。可下载签发证书。
3. 让两个客户端分别点击「持证连接」。选中在线收件人并点击「协商会话密钥」，等待两端显示已启用 AES-256-GCM，再发送消息并从另一端回复。
4. 在「TLS 对照」点击「运行对照」，查看单向 TLS、双向 TLS 缺客户端证书、自签名证书的默认信任与显式信任四个实测结果。
5. 管理员停用其中一张证书，确认该客户端离线。点击「重连验证」，会看到聊天服务拒绝旧证书的 HTTP 403。该账号重新生成 CSR、提交并获签后，用新证书上线，重新协商后发送消息。展开「已停用证书」，选择对应序列号再次验证旧证书，确认旧证书依然被拒绝。
6. 登录管理员后打开「认证记录」。按账号、申请编号、证书指纹、会话编号或 `#连接编号` 筛选，展开原始日志，或下载筛选结果为 NDJSON。实时视图显示本场最近 80 条事件，历史记录可按场次查阅。

| 想说明的原理 | 可核对的记录 |
| --- | --- |
| 签发证书对应提交的 CSR | CSR 验签通过，CSR 与证书的 SPKI SHA-256 摘要相同，证书的 CA 签名校验通过 |
| 持证接入 | 按申请编号关联 `certificate_issued`、`tls_established` 和 `websocket_admission` |
| 两端认证并派生密钥 | 两端显示同一会话编号和协商记录 SHA-256 摘要。用会话编号找到 `session_relayed` 的发起、应答和确认帧 |
| 密文转发与篡改拒绝 | 对照两端聊天记录和 `message_relayed` 的密文片段、序号。发篡改测试包后，接收端的完整性拒绝次数增加，聊天记录不增加 |
| 缺证与停用触发不同层的拒绝 | 缺证出现 `tls_rejected`。停用证书在仍有效且受信任时可以完成 TLS 握手，随后同一连接的接入记录为 `certificate_revoked` 和 HTTP 403 |
| 换证为何可以恢复 | 同账号的新申请、序列号和证书指纹与旧证书不同。新证书接入为 HTTP 101，旧证书的独立验证仍为 HTTP 403 |

本机应用监听回环地址。启动终端也会打印同一界面的单向 HTTPS 地址。直连 HTTPS 时浏览器需信任 `.prototype/course-app/ca/ca.crt`。默认的本机 HTTP 页面供无需导入证书的演示使用，聊天代理到聊天服务的传输使用两个各自持证的 mTLS 连接。

账号、申请和签发状态存于本机 SQLite，CSR 草稿保存在独立的 `certificate-drafts.sqlite`。课程私钥和初始管理员密码留在 `.prototype/course-app/`。`npm test` 会使用隔离运行目录执行完整生命周期和 TLS 对照。

### 双人密钥协商与密文演示

1. 在两端的「本端会话」中展开对方的会话。页面为每个对端分别显示成功解密和完整性拒绝次数，收件人选择用于发送。每个端点用实验 CA 核对对端证书、证书主体及有效期，再用证书公钥验证临时 X25519 公钥的 RSA-PSS 签名。应答签名绑定双方临时公钥和协商记录。
2. 两端通过 X25519 计算共享秘密，以 HKDF-SHA256 派生两个方向的 AES-256-GCM 密钥，并验证对端的密钥确认标签。消息序号参与完整性验证，接收端拒绝已处理的序号。同一账号与不同收件人会单独协商。
3. 发一条正常消息，对照发送端、接收端和管理员时间线的密文片段。点击「发送篡改测试包」会生成固定测试内容，并在发出前修改认证标签。在接收端检查拒绝次数，再发一条正常消息确认会话仍可用。协商详情仅显示公共握手记录摘要和证书指纹，日志只保留密文片段与转发元数据。

`npm run demo` 在同一 Node.js 进程内运行客户端代理与中转模块。密钥协商、加密和解密发生在各代理，中转模块接收并转发协商帧和密文。

## 单机独立服务端与双客户端

### 一键启动

在仓库根目录打开 PowerShell。环境需要 Node.js 24 或更新版本、PATH 中的 OpenSSL 3。第一次运行或更换依赖版本时先运行 `npm ci`。

```powershell
npm ci
npm run demo:all
```

等终端显示「三个进程均已就绪」，再打开下表中的网页。使用自定义端口时，以启动终端列出的地址为准。演示结束后在启动终端输入 `quit` 或按 Ctrl+C。若提示端口已占用，先在原来的终端停止对应的演示进程。

| 页面 | 默认入口 | 默认运行目录 |
| --- | --- | --- |
| 实验台与证书审批 | [实验台](http://127.0.0.1:18447/#admin) | `.prototype/course-server/` |
| Alice | [Alice 客户端](http://127.0.0.1:18450/) | `.prototype/course-clients/alice/` |
| Bob | [Bob 客户端](http://127.0.0.1:18451/) | `.prototype/course-clients/bob/` |

### 申请、连接与加密收发

1. 在 Alice、Bob 页面分别点「生成 CSR 并申请」。首次启动会自动注册两个账号。若已有证书，看到「已签发」可直接持证连接，看到「待审批」可直接去审批，看到「已停用」或「已过期」可重新申请。
2. 打开实验台的「证书审批」，从服务端终端显示的 `admin-password.txt` 读取密码。默认路径为 `.prototype/course-server/admin-password.txt`。输入管理员密码并点击「登录管理员」，分别点 Alice 和 Bob 的「审批签发」。
3. 两端的证书状态更新为「已签发」后，分别点「持证连接」。在 Alice 页面选择 Bob，点「协商会话密钥」。两端应显示「AES-256-GCM 已启用」。「密钥协商记录」中的会话编号与协商摘要应一致。
4. 在 Alice 页面发送一条消息，再从 Bob 页面回复。两端应收到对方的明文。展开消息中的「密文片段」，可以和实验台「认证记录」里的会话编号、序号和密文片段对照。
5. 在实验台打开「TLS 对照」，点「运行对照」。可核对单向 TLS、双向 TLS 缺证书、自签名证书默认信任与显式信任四项结果。

### 篡改拒收和停用换证

- **篡改拒收。** 两端完成协商后，Alice 点「发送篡改测试包」。Bob 应显示「完整性校验已拒收 1 条消息」，聊天记录里不出现测试内容。再从 Alice 发一条正常消息，Bob 应能解密。重复测试时，拒收次数会累加。
- **停用和旧证复核。** 在「证书审批」停用 Alice 当前仍在有效期内的证书。Alice 应断线，点「用旧证书重连验证」应显示 HTTP 403，Bob 仍在线。随后在 Alice 页点「重新申请证书」，由管理员签发，用新证书连接并重新协商。展开「已停用证书」，选择旧序列号，点「复核旧证书」。即使旧证书返回 HTTP 403，新会话也应继续收发。

### 分别启动三个进程

想单独检查退出与重启时，在同一台电脑的三个终端分别运行下列命令。等服务端就绪后再启动客户端。

| 终端 | 命令 |
| --- | --- |
| 服务端 | `npm run demo:server` |
| Alice | `npm run demo:client -- alice` |
| Bob | `npm run demo:client -- bob` |

在 Alice 终端输入 `quit`，Alice 网页应显示客户端进程未响应，Bob 和服务端继续运行。重新运行 Alice 的启动命令并持证连接即可恢复。客户端终端也支持 `request`、`status`、`connect`、`negotiate <账号>`、`send <账号> <消息>` 和 `disconnect`。

客户端启动时读取服务端的公共 CA 证书，默认是 `.prototype/course-server/ca/ca.crt`。每个客户端的私钥留在自己的运行目录，签发证书首次持证连接时写入同一目录。服务端保存 CA、服务端密钥及申请和签发状态。

服务端管理网页与客户端 HTTPS 的默认端口分别是 `18447`、`18448`，可用 `COURSE_PORT`、`COURSE_API_PORT` 更改。分别启动时，客户端可用 `COURSE_CLIENT_PORT` 更改自己的网页端口。一键启动可用 `COURSE_ALICE_PORT`、`COURSE_BOB_PORT` 分别设置两个页面端口。可用 `COURSE_RUNTIME_DIR`、`COURSE_CLIENT_ROOT` 指定运行目录。若分别启动且更改了服务端目录，在客户端设置 `COURSE_CA_FILE` 指向该服务端的公共 CA 证书。

### 立即复现证书到期与续签

正常签发的证书有效期为 7 天。下面的演练使用一份新建的本地数据和一张 90 秒有效的测试证书。可同时保留日常演示运行的数据。

1. 在仓库根目录的第一个 PowerShell 窗口运行下列命令，保留终端中输出的「演练目录」。每次执行都会创建新的运行目录。

```powershell
$demoDir = Join-Path (Get-Location).Path ".prototype/expiry-rehearsal-$(Get-Date -Format yyyyMMdd-HHmmss-fff)"
$env:COURSE_RUNTIME_DIR = Join-Path $demoDir 'server'
$env:COURSE_CLIENT_ROOT = Join-Path $demoDir 'clients'
$env:COURSE_CA_FILE = Join-Path $env:COURSE_RUNTIME_DIR 'ca/ca.crt'
$env:COURSE_PORT = '18457'
$env:COURSE_API_PORT = '18458'
$env:COURSE_ALICE_PORT = '18459'
$env:COURSE_BOB_PORT = '18460'
Write-Host "演练目录 $demoDir"
npm run demo:all
```

2. 等三个进程就绪，打开 [演练用 Alice](http://127.0.0.1:18459/)，点「生成 CSR 并申请」，停在「待审批」。这次由第二个终端把同一个 CSR 登记成短期测试证书。

3. 在仓库根目录的第二个 PowerShell 窗口运行下列命令，按提示粘贴第一步的演练目录。成功后会打印公开证书路径和到期时间。

```powershell
$env:COURSE_EXPIRY_DEMO_ROOT = Read-Host '粘贴第一个终端的演练目录'
@'
import { readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { saveDatedCertificate } from './app/test-certificate.ts';

const root = resolve((process.env.COURSE_EXPIRY_DEMO_ROOT ?? '').trim());
if (dirname(root) !== resolve('.prototype') || !basename(root).startsWith('expiry-rehearsal-')) {
  throw new Error('请选择第一步输出的独立演练目录。');
}
const { id, csr } = JSON.parse(readFileSync(join(root, 'clients', 'alice', 'initial-request.json'), 'utf8'));
const opensslTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace(/[-:T]/g, '') + 'Z';
const now = Date.now();
const pem = saveDatedCertificate(join(root, 'server'), id, csr, opensslTime(now - 60_000), opensslTime(now + 90_000));
const output = join(root, 'alice-short-lived.crt');
writeFileSync(output, pem, { flag: 'wx' });
console.log('公开证书 ' + output);
console.log('到期时间 ' + new X509Certificate(pem).validToDate.toLocaleString('zh-CN'));
'@ | node --input-type=module -
```

4. 回到 Alice 页，等状态变为「已签发」，立即点「持证连接」。证书到期后，应出现「已过期」并自动断开聊天。若打开页面时证书已经到期，可以直接继续下一步。
5. 在 Alice 页点「重新申请证书」。打开 [演练用证书审批](http://127.0.0.1:18457/#admin)，用第一个终端打印的管理员密码文件登录并签发。Alice 用新证书可重新连接。若要验证加密收发，在 [演练用 Bob](http://127.0.0.1:18460/) 申请、获签并上线，再和 Alice 重新协商。
6. 在演练用实验台点击「证书在线查验」，选择第三步输出的 `alice-short-lived.crt`，点「查验 PEM 证书」。预期 **实验 CA 签名通过、有效期已过期、登记状态已登记**。在「认证记录」筛选 `certificate_expired`，可看到已连接的证书到期后被断开的记录。

也可在仓库根目录运行下列命令，让测试自动启动隔离的服务端和客户端，检查短期证书到期断线、重新申请、新证书接入和归档跨重启。

```powershell
node --test app/standalone.test.ts
```

## 证书在线查验

在「证书审批」登录管理员，然后打开「证书在线查验」。在登记证书下拉框选一张证书后点「查验登记证书」，或从文件读取和粘贴单张 PEM 公开证书，再点「查验 PEM 证书」。

| 对照场景 | 预期结果 |
| --- | --- |
| 本实验 CA 签发、在有效期、已登记 | 显示「有效」 |
| 在有效期内的证书被管理员停用 | CA 签名通过，登记状态「已停用」 |
| 本实验 CA 签发的证书已过期 | CA 签名通过，有效期「已过期」 |

独立客户端首次持证连接后，可按「证书信息」中的申请编号，在 `.prototype/course-clients/<账号>/<申请编号>.crt` 找到对应的公开证书用于文件查验。短期演练中的公开证书请在该演练的实验台查验。

## 按场次核对和导出认证记录

1. 完成一次签发、协商和加密发送。在实验台「认证记录」的「演示场次」选择「本场已归档记录」，在「筛选记录」输入 `转发密文`，或输入客户端「密钥协商记录」里的会话编号。
2. 点「下载筛选记录」，打开下载的 `.ndjson` 文件。正常加密消息对应 `message_relayed`，可核对会话编号、密文片段和消息序号。
3. 在一键启动终端输入 `quit`，用相同运行目录重新启动并登录管理员。从「演示场次」选择上一次启动时间。应能再次看到同一批历史记录。查看刚写入的记录时，可点「刷新场次记录」。

默认视图显示本场最近 80 条实时记录。每次启动在服务端运行目录的 `evidence/` 保存一个独立归档文件，默认路径为 `.prototype/course-server/evidence/`。

## 双向 TLS 网页原型

### 一页演示

运行下列命令，在浏览器打开 [本机演示页](http://127.0.0.1:18444/)。

```powershell
npm ci
npm run demo:prototype
```

演示服务启动时自动生成一组独立的测试证书，为 Alice 和 Bob 分别建立 mTLS 连接。页面打开后两端自动连上，可以从左右两栏收发消息，也可以用「验证无证书」查看握手拒绝、用「停用 Bob 并重连」查看服务器拒绝接入，随后恢复 Bob。

演示页仅监听本机，页面通过本机演示服务操作两个持证连接。测试私钥留在服务端临时目录内，浏览器无需导入证书。这组测试证书与独立原型的证书目录分开。端口可通过 `DEMO_PORT` 指定。

### 复核认证证据

网页下方的「认证过程与服务端证据」显示运行时记录。运行 `npm run demo:prototype` 的终端会同步输出 JSON 事件，网页可以下载最近 80 条 NDJSON 记录。

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
