# secrets-web

*English: [README.md](README.md)*

一个自托管的小型网页，用来查看和维护一个用 [age](https://age-encryption.org) 加密的密钥 git 仓 —— 也就是 `secret` CLI
管理的同一个仓。它读取裸仓，用**自己的** age identity 在**服务端**解密，通过任意 OpenID Connect 提供方登录（文档以
Google 为例），并且可选地用 deploy key 提交、推送来新增 / 编辑 / 删除条目。

- **格式**：数据布局（`catalog.toml`、`recipients.toml`、`policy.toml`、`store/<domain>/<group>/<name>.<kv|file|doc>.age`、
  `store/.recipients.lock`）由 [`../FORMAT.md`](../FORMAT.md) 定义。本服务实现其中的受限 TOML、recipients、glob / 收件人集合哈希、
  catalog、kv 与密文合法性规则，读取方式与 CLI 完全一致。
- **技术栈**：ASP.NET Core（.NET 10）Razor Pages，没有前端构建链、不引外部脚本，`git` 与 `age` 以子进程方式调用。

> **部署前请先读「安全模型」。** 本服务能解密所有加密给它的 identity 的密钥。
> 在 Production 环境下，如果没有声明它前面的网络访问层，它会拒绝启动。

## 架构

```
浏览器（手机 / 电脑）
   │  HTTPS
   ▼
你的访问层 / 反向代理                        （VPN、mesh VPN、身份感知代理、带认证的反向代理……）
   │  http://127.0.0.1:8099
   ▼
secrets-web 容器                            （非 root、只读根文件系统、不留任何 capability）
   ├─ OIDC 依赖方（RP） ──────────────►     你的 OpenID Connect 提供方（授权码 + PKCE，只认 RS256 id_token）
   ├─ git --git-dir /repo                   裸仓，只读挂载
   │     rev-parse HEAD / cat-file blob <commit>:catalog.toml | store/…
   ├─ age -d -i /identity/identity.txt      密文走 stdin，明文走 stdout，只在内存
   ├─ /data/audit.log                       JSONL 审计
   └─（可选）/data/work → git push           写入：工作区 clone + deploy key → 你的 git 服务器
```

| 目录 | 内容 |
|---|---|
| `src/SecretsWeb/Format/` | 手写的受限 TOML 解析器、catalog / recipients 校验、kv 解析、路径与密文头规则、glob 与收件人集合哈希、规范形态 TOML 写出 |
| `src/SecretsWeb/Repo/` | 子进程封装（stdin 喂密文、stdout 设上限、环境变量白名单）、按 HEAD 缓存 catalog 的裸仓读取、写入（工作区 clone → commit → push） |
| `src/SecretsWeb/Security/` | OIDC / cookie 配置、独立的 id_token 校验器、内存 `ITicketStore`、安全响应头、PublicOrigin 改写、频控、启动期护栏（访问层、可信代理） |
| `src/SecretsWeb/Services/` | 解密 + 审计（`EntryService`）、写入（`EntryWriteService`）、健康检查、Markdown 渲染、收藏 |
| `src/SecretsWeb/Pages/` | Razor Pages：列表 / 树 / 搜索、条目页、新增 / 编辑 / 删除 |
| `src/SecretsWeb/wwwroot/` | `app.css`、`app.js`、`form.js`（无内联脚本） |
| `tests/SecretsWeb.Tests/` | xUnit：格式单测 + 基于临时测试仓的集成测试 |
| `deploy/docker-compose.yml` | 部署样例 |

## 安全模型

**服务端解密。** 浏览器从不持有密钥。容器持有一个 age identity，按请求解密，所以*谁控制了这个服务、或者能登录它，谁就能读到
所有加密给这个 identity 的条目*。由此：

- **给它一个专用收件人。** 为网页新生成一个 identity（`age-keygen -o identity.txt`），把公钥登记成 `service` 类型的收件人
  （`secret recipients add web <age1…> --type service`），然后重新加密（`secret rekey`）。绝不复用设备或恢复用的 identity。
- **只把网页需要的加密给它。** `policy.toml` 决定谁能解密什么，最后一条匹配的规则生效。例如只让网页收件人参与一个 domain：

  ```toml
  [[rule]]
  path = "store/**"
  recipients = ["@device", "@recovery"]

  [[rule]]
  path = "store/personal/**"
  recipients = ["@device", "@recovery", "web"]
  ```

  它解不开的条目会出现在列表里，但打不开。写入也受同样的限制：加密之后服务会把自己的输出解密回来做自检，所以它无法新建或
  编辑它读不了的条目。
- **必须放在网络访问层后面。** 对一个手握解密密钥的服务，只靠 OIDC 登录是不够的。让它只绑 `127.0.0.1`，只通过先对网络路径
  做认证的东西对外发布（VPN 或 mesh VPN、Cloudflare Access 这类身份感知代理、带认证的反向代理）。`Deployment:AccessLayer`
  必须描述这一层；Production 环境下不填就拒绝启动。填 `none` 仍会启动，但日志里会有醒目的警告。
- **作废靠轮换。** 删掉条目或收件人并不能把已泄露的收回：git 历史里还有旧密文。如果网页的 identity 可能泄露了，移除该收件人、
  rekey，并轮换它能读到的所有值。

**登录。** 只做 OIDC 依赖方（授权码 + PKCE，confidential client）。OIDC 处理器对 token 端点返回的 id_token 并不是每种形态都
强制验签（`alg=none`、RS256 头 + 空签名段），所以 `OnTokenValidated` 里会对原始 id_token 再独立完整验一遍：签名段非空、header
`alg` 必须是 RS256、只用 JWKS 里的 RSA 钥匙、`RequireSignedTokens`、`iss`、`aud = ClientId`、有效期。签名 / 钥匙类失败会强制
刷新一次 JWKS（最短间隔 60 秒），IdP 轮换钥匙后不至于把你挡在外面，已摘掉的钥匙也不再被接受。不注册 JwtBearer，不接受任何
bearer / access token。`SaveTokens = false`；登录后会话 principal 只保留 `sub`、`name`、一个随机会话 id，以及**仅当 IdP 标记为
已验证时**的邮箱。是否放行由白名单（`Auth:AllowedSubjects`、`Auth:AllowedEmails`、可选的 `Auth:RequireAmr`）决定：登录时校验，
授权层 fallback policy 再校验，每个请求的 `OnValidatePrincipal` 还校验一次，所以把某人移出白名单不用重启就生效。`returnUrl`
只接受站内相对路径（`/…`、`IsLocalUrl` 为真、不含控制字符与反斜杠）。登录被拒时，页面会给调用者看**他自己的** `sub` / 邮箱，
并提示加到哪个配置项里才能放行。

**会话。** `__Host-secrets-web` cookie 只放一个随机会话 id（服务端内存票据），HttpOnly + Secure + SameSite=Lax、非持久；空闲 15
分钟滑动过期，自登录起 8 小时绝对过期。进程重启 = 所有人退出。退出时如果 IdP 发布了 `end_session_endpoint` 就走 RP-initiated
logout；否则（Google 就没有）只清本地会话。

**取值。** 列表、搜索以及 kv 与 file 条目的 GET 页面都不解密；kv 每次点击只解一个字段。取值接口只接受 POST，需要 antiforgery
token（`__Host-` cookie，SameSite=Strict）加自定义头 `X-Secrets-Web`；下载是带 token 的表单 POST。显示出来的值 30 秒后重新遮罩。
`doc` 条目只有同源导航（`Sec-Fetch-Site: same-origin | none`）时才在 GET 上解密，否则放在一个按钮后面。

**明文处理。** 密文经 stdin 交给 `age -d`，明文从 stdout 读进定长缓冲，从不落盘；超过上限即杀进程；用完的字节数组尽力清零。
读 catalog 与读密文钉在同一个 commit 上。

**校验。** catalog / recipients 按受限 TOML 子集解析（子集外一律报错）；密文路径做正则 + 保留名排除；必须有
`age-encryption.org/v1\n` 头；kv 严格解析且字段集合必须与 catalog 一致。任何一项不满足都是错误，从不猜。只有 TOML 语法错误、
`[[meta]] format` 缺失或不认识、仓不可读会让整站 503；其余问题只让那一条条目不可用，显示原因、不解密。

**审计。** 每次解密（含失败）写一行 JSONL：`ts / event / sub / path / field / action / result / reason / suppressed_before / ip`
—— **结构上就没有值字段**。审计写不进去就不返回明文（fail closed；写失败时先轮转再重试一次，因为磁盘写满时轮转恰好是能救命
的动作）。登录（成功、失败、被拒）与写入同样记审计，不含值。匿名回调上的失败行按客户端 IP 限流（每分钟 10 行，全局 60 行；
被压下的行数记在 `suppressed_before`）。限流 key 只用客户端 IP —— 客户端能自己设置的请求头绝不影响它。放在反向代理后面时，
请配置 `Network:KnownProxies`，让服务拿到真实客户端 IP；否则所有请求看起来都来自代理，按 IP 限流实际上就成了全局限流。
`ip` 字段仅供参考。

**频控与告警。** 每会话：每分钟 20 次解密、每小时 200 次（超出 429），每分钟 10 次写入。频控 key 用存在票据里的随机会话 id，
而不是 cookie 串（滑动续期会重签 cookie）。以下情况会告警：登录失败、非白名单账号、`amr` 不满足、10 分钟内解密的不同条目超过
30 个、10 分钟内改动的不同条目超过 5 个；10 分钟最多 1 条；告警内容从不含条目名或 subject。

**响应头。** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`、`X-Frame-Options: DENY`、
`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff`，所有响应 `Cache-Control: no-store`，HTTPS 下带 HSTS。

**Markdown。** 禁用原始 HTML，不启用 generic attributes；链接只保留 http / https / mailto / 站内相对（其余改成 `#`），统一
`rel="noopener noreferrer"`；外链图片替换成 alt 文本（否则会泄露查看时间和你的 IP），CSP 再挡一层。

**子进程。** `git` / `age` 不经 shell 启动，环境变量按白名单重建（`PATH`、`HOME`、`TZ`、locale、临时目录、Windows 上几个进程
创建必需项，外加固定的 `GIT_CONFIG_NOSYSTEM=1`、`GIT_TERMINAL_PROMPT=0`、`LC_ALL=C`）。OIDC client secret 与告警 webhook token
不会传给它们。最多同时 4 个；`/health` 结果缓存 10 秒。

**容器。** 非 root（UID 1654）、只读根文件系统、`cap_drop: ALL`、`no-new-privileges`、只绑 127.0.0.1；裸仓与 identity 只读挂载。
镜像请在运行它的主机上构建，不要放到共用的 CI 上。

## 写入（新增 / 编辑 / 删除）

可选功能：`Repo:PushUrl` 为空时实例是只读的（写接口返回 400，页面不显示写入入口）。**读路径不变，仍然读只读挂载的裸仓。**
写入走另一条路：

```
表单 → /api/entry/*  →  工作区 clone（/data/work）
                         ├─ fetch 裸仓 + reset --hard（工作区是派生物，随时可丢）
                         ├─ 写入前校验：catalog ↔ store ↔ lock 必须一一对应，目标密文还要与 lock 里的 CHash 相符
                         │             （对不上 = 有人绕过 CLI 改过密文：拒写，保留证据）
                         ├─ 改动：按 policy.toml 展开的收件人做 age 加密 → 立刻解回来比对 SHA-256
                         │        → 写 .age → 更新 catalog.toml（规范形态，保留未知键）→ 更新 lock
                         ├─ 写入后再校验一次；不通过就 git reset --hard 且不 push
                         ├─ commit（作者 = secrets-web，消息 `web: add personal/x/y (kv)`）
                         └─ git push（deploy key，ssh）→ 裸仓更新，下一次读就是新的
```

- **冲突**：进程内单写锁；push 被拒（CLI 先推了）→ 重新 fetch，在新 HEAD 上**只重放这一条操作**（不是 rebase），最多 3 次，
  之后返回 409。
- **乐观并发（强制）**：编辑页带着打开那一刻的条目块指纹；`/api/entry/update` **不带指纹一律 400**，指纹对不上返回 409
  （「重新载入再改」）。
- **删除前看引用**：确认页与删除响应都会列出 `readers`、`linked` 以及谁链到了它；有入链时**拒绝删除**（409 + 列出引用方）——
  先改掉那些引用，或在命令行用 CLI 强制删除。
- **别名**写入前规范化（去 `[[ ]]`、反斜杠转正斜杠、去 `.md`、NFC），与 CLI 存的是同一个串。
- **catalog 键序**严格照 FORMAT，未知键保留在 `updated` 之后，文件开头的注释保留，CLI 与网页交替写不会产生无谓的 diff。
  有逐字节的回归测试。
- **明文不落盘**：值只在内存与到 `age` 的管道里；有回归测试逐字节扫工作区。
- **删除**会删掉密文、catalog 条目和 lock 行。旧密文还留在 git 历史里；真正作废要去签发它的地方轮换值。

## 配置

所有配置都可以用环境变量覆盖（`:` 换成 `__`，数组元素用 `__0`、`__1`……）。**`Auth__ClientSecret` 与 `Alerts__WebhookToken`
只放 `.env`**，不写进 appsettings、compose 文件或任何仓。

| 键 | 默认 | 说明 |
|---|---|---|
| `PublicOrigin` | 空 | 对外原点，如 `https://secrets.example.com`。每个请求的 Scheme/Host 都改写成它（redirect_uri 与 Secure cookie 依赖它）。**Production 必填** |
| `Deployment:AccessLayer` | 空 | 自由文本，说明是什么在保护这个服务，如 `tailscale`、`cloudflare-access`、`vpn`、`reverse-proxy`。**Production 必填**（为空拒绝启动）；填 `none` 会启动但打醒目警告。Development 环境不强制 |
| `Network:KnownProxies` | `[]` | 可信反向代理的 IP。它或 `KnownNetworks` 非空时，只接受来自这些对端的 `X-Forwarded-For` / `X-Forwarded-Proto`（只信一跳；框架默认对回环地址的信任会被清掉）。为空 = 忽略所有转发头 |
| `Network:KnownNetworks` | `[]` | 可信反向代理的 CIDR 网段，如 `10.0.0.0/8` |
| `Auth:Authority` | 空 | OIDC issuer，如 `https://accounts.google.com`。**必填** |
| `Auth:ClientId` | `secrets-web` | 在 IdP 登记的 client id |
| `Auth:ClientSecret` | 空 | **只从环境变量注入**，必填 |
| `Auth:CallbackPath` | `/signin-oidc` | 必须与在 IdP 登记的回调地址（`<PublicOrigin>/signin-oidc`）一致 |
| `Auth:Scopes` | `openid email profile` | 用 `AllowedEmails` 需要 `email` |
| `Auth:Resource` | 空 | 非空时授权请求附带 RFC 8707 `resource=` 参数 |
| `Auth:AllowedSubjects` | `[]` | 允许登录的 id_token `sub`（精确、区分大小写） |
| `Auth:AllowedEmails` | `[]` | 允许登录的邮箱（去空白、不区分大小写），**只在 id_token 的 `email_verified` 为 true 时生效**（JSON 布尔或字符串 `"true"`）。两个白名单至少要有一个非空，否则启动失败 |
| `Auth:RequireAmr` | 空 | 非空时要求 id_token 的 `amr` 含该值 |
| `Auth:IdleTimeoutMinutes` | 15 | 空闲滑动过期 |
| `Auth:MaxLifetimeHours` | 8 | 自登录起绝对过期 |
| `Repo:GitDir` | `/repo` | 裸仓路径 |
| `Repo:Identity` | `/identity/identity.txt` | age identity 文件 |
| `Repo:GitPath` / `Repo:AgePath` | `git` / `age` | 可执行文件 |
| `Repo:CommandTimeoutSeconds` | 30 | 子进程超时 |
| `Repo:FileTextMaxBytes` / `FileMaxBytes` / `DocMaxBytes` | 256 KB / 1 MB / 1 MB | 大小上限（file 条目的文本显示 / file 条目与上传 / doc 条目） |
| `Repo:PushUrl` | 空 | 写入用的推送地址，如 `ssh://git@git.example.com/you/secrets.git`。**为空 = 只读实例** |
| `Repo:Branch` | `main` | 推送的分支 |
| `Repo:WorkDir` | `/data/work` | 写入用的工作区 clone（必须可写） |
| `Repo:SshKey` / `Repo:KnownHosts` | 空 | deploy key 与 known_hosts（只读挂载），组装成 `GIT_SSH_COMMAND`（`IdentitiesOnly=yes`、`StrictHostKeyChecking=yes`、`BatchMode=yes`） |
| `Repo:CommitAuthorName` / `CommitAuthorEmail` | `secrets-web` / `secrets-web@localhost` | 网页提交的作者与提交者 |
| `Repo:FavoritesPath` | `/data/favorites.json` | 服务端收藏（只给网页用，不属于数据仓） |
| `Audit:Path` | `/data/audit.log` | JSONL 审计日志 |
| `Audit:MaxBytes` / `Audit:KeepFiles` | 8 MB / 5 | 轮转成 `audit.log.1 … .N`（POSIX 下新文件 0600）；`MaxBytes <= 0` 关闭轮转 |
| `DecryptLimits:PerMinute` / `PerHour` | 20 / 200 | 每会话解密次数；超出 429 |
| `DecryptLimits:WritePerMinute` | 10 | 每会话每分钟写入次数 |
| `DecryptLimits:DistinctWindowMinutes` / `DistinctThreshold` | 10 / 30 | 窗口内解密的不同条目超过阈值 → 告警一次（不含条目名） |
| `Alerts:WebhookUrl` | 空 | 告警以 JSON `{"title": "...", "text": "...", "severity": "warning"}` POST 到这里。为空 = 只写日志 |
| `Alerts:WebhookToken` | 空 | 可选，作为 `Authorization: Bearer <token>` 发送。**只放环境变量** |
| `Alerts:MinIntervalMinutes` | 10 | 每个窗口最多一条告警；被压下的次数带在下一条里 |
| `Alerts:WriteDistinctEntries` / `Alerts:WriteWindowMinutes` | 5 / 10 | 窗口内改动的不同条目超过阈值 → 告警一次（不含条目名） |

告警 webhook 刻意做成通用的：把它指向一个转发到你的聊天工具或值班系统的小中继即可（载荷从不含条目名，转发到聊天群是安全的）。

## 用 Google 作为 OpenID Connect 提供方

1. 在 Google Cloud 控制台打开 **APIs & Services → OAuth consent screen** 并完成配置。个人使用选 "External"、保持测试模式、
   把自己加为测试用户即可；Google Workspace 组织内使用选 "Internal"。`openid`、`email`、`profile` 都是非敏感 scope。
2. **APIs & Services → Credentials → Create credentials → OAuth client ID**，应用类型选 **Web application**。
   在 **Authorized redirect URIs** 里添加 `<PublicOrigin>/signin-oidc`，如 `https://secrets.example.com/signin-oidc`。
   不需要填 JavaScript origins。
3. 配置本服务：
   - `Auth__Authority=https://accounts.google.com`
   - `Auth__ClientId=<client id>.apps.googleusercontent.com`
   - `Auth__ClientSecret=<client secret>` —— **只放 `.env`**
4. 把自己加进白名单，二选一：
   - 按邮箱：`Auth__AllowedEmails__0=you@example.com`（Google 账号的邮箱会被标记为已验证；未验证的邮箱永远匹配不上）；
   - 按 subject：先登录一次 —— 「Access denied」页面会显示你的 `sub`（一个稳定的 Google 账号数字 id）—— 然后设置
     `Auth__AllowedSubjects__0=<sub>`。subject 不会变、也不会被重新分配，是更严格的选择。
5. 退出：Google 没有 `end_session_endpoint`，所以退出只清掉本服务的会话，浏览器里的 Google 登录状态还在。在共用设备上请顺手
   退出 Google。

其他 OIDC 提供方同理，只要支持授权码流程 + PKCE、confidential client（`client_secret_post`）、`response_mode=query`，以及
RS256 签名的 id_token。

## 部署

1. **Identity**：`age-keygen -o identity.txt`，`chown 1654:1654 identity.txt`，`chmod 600 identity.txt`。把公钥
   （`age-keygen -y identity.txt`）登记为 `service` 收件人并 rekey（见「安全模型」）。
2. **仓**：在 `deploy/repo.git` 放一份 UID 1654 可读的密钥仓裸仓（或者把 git 服务器自己的裸仓只读挂进来），并保持更新，
   例如直接挂 git 服务器那份，或者让写入端推到它。
3. **写入（可选）**：一把对该仓有写权限的 deploy key（`deploy_key`，600，属主 1654）和一个含 git 服务器 host key 的
   `known_hosts`；设置 `Repo__PushUrl`。只读实例留空 `Repo__PushUrl`。
4. **数据目录**：`mkdir data && chown 1654:1654 data`（审计日志、收藏、工作区 clone）。
5. **`.env`**（600）：`Auth__ClientSecret=…`，可选 `Alerts__WebhookUrl=…`、`Alerts__WebhookToken=…`。
6. **构建**：在 `web/` 下、在运行它的主机上执行 `docker build -t secrets-web:local .`。
7. **启动**：按实际情况改 `deploy/docker-compose.yml`（PublicOrigin、Authority、ClientId、白名单、AccessLayer、PushUrl），
   然后 `docker compose up -d`。
8. **发布**：`127.0.0.1:8099` 只经你的访问层对外。如果代理从别的地址连过来（容器网络、另一台主机），把
   `Network__KnownProxies__0` / `Network__KnownNetworks__0` 设成恰好是那个代理。
9. **验收**：`curl -s http://127.0.0.1:8099/health` 返回 `status: ok` 且 `head` 等于仓 HEAD（`secret check --web <url>` 也会查
   这个）；登录、查看、复制各一次，检查 `data/audit.log`；确认绕过访问层访问不到本服务。

## 页面与接口

| 路径 | 说明 |
|---|---|
| `GET /` | 按 domain / group 的树；`?q=` 搜索 path、标题、描述、标签。只读 catalog，不解密 |
| `GET /entry/<domain>/<group>/<name>` | 条目页。`doc` 仅当 `Sec-Fetch-Site` 为 `same-origin` / `none` 时解密渲染（审计 `view`），否则显示「Click to view」按钮（POST + antiforgery）；`kv` 列字段名、值遮罩；`file` 只给按钮；元数据不合法的条目显示原因、不解密 |
| `POST /api/field` | 解密 kv 的**一个**字段（`mode=show|copy`），需 antiforgery token + `X-Secrets-Web` 头 |
| `POST /api/file` | `file` 条目：UTF-8 文本且 ≤ 256 KB 时返回文本，否则只返回大小；需 token + 自定义头 |
| `POST /api/download` | `file` 下载（≤ 1 MB）；表单 POST + antiforgery token |
| `POST /api/favorite` | 切换收藏（服务端文件，不解密、不审计）；需 token + 自定义头 |
| `GET /new` | 新增表单（只读实例不显示） |
| `GET /entry/<path>/edit` | 编辑表单（GET 不解密；「Load current content」是 POST，会解密并记审计） |
| `GET /entry/<path>/delete` | 删除确认页，发一次性 token（绑会话 + path，5 分钟） |
| `POST /api/entry/create` / `update` / `delete` | 写入接口（multipart 表单）。与解密接口同一套防护：POST + antiforgery + `X-Secrets-Web` + 白名单 + 频控；删除还要一次性 token |
| `GET /login` / `POST /logout` | 发起 OIDC 登录 / 退出（删服务端会话，IdP 支持时走 RP-initiated logout） |
| `GET /health` | 匿名，缓存 10 秒：`{status, head, format, entries, invalidEntries, consistency: {consistent, catalogEntries, storeFiles, lockLines}}`。只有 TOML 语法错误、format 缺失或不认识、仓不可读时 `status=error` / HTTP 503。从不含条目名 |

## 开发与测试

需要 PATH 里有 `git`、`age`、`age-keygen`，以及 .NET 10 SDK。

```
dotnet test
```

集成测试在临时目录生成测试 identity，用 age CLI 加密随机测试值，建测试裸仓，再用 `WebApplicationFactory` 加测试认证方案或假
IdP 跑起来。不接触任何真实数据。`Development` 环境下不强制访问层检查。
