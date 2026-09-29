# secret-run

**让密钥的值不进 AI 编程助手的上下文。** 一个小型密钥管理工具：数据是私有 git 仓里的纯 [age](https://age-encryption.org) 密文；CLI 只把值注入子进程、子进程把值打出来时自动遮掉；另有一个可选的自建网页端给人用。

English: [README.md](README.md)

## 为什么

AI 编程助手会读文件、跑命令、留会话记录。`.env`、笔记或者命令输出里的一个 key，会进上下文、落进本机的会话记录文件，还经常引发一轮又一轮"你的密钥泄露了"的提示。secret-run 的做法是：文档和提示词里只写**指针**（`secret:work/chat/bot-app#APP_SECRET`），值直接送到需要它的进程：

```
secret run -e APP_SECRET=work/chat/bot-app#APP_SECRET -- python notify.py
```

- 值只存在于子进程的环境变量里——不在 AI 发出的命令行里，也不在用户级环境变量里。
- 子进程万一把它打了出来、而输出正被捕获（被 AI、日志、管道），出来的是 `<concealed:APP_SECRET>`。

## 工作方式

```
                 你的私有 git 仓（数据）
   recipients.toml · policy.toml · catalog.toml · store/**/*.age
        ▲  git pull / push                      ▲  只读裸仓
        │                                       │
 ┌──────┴─────────────────────┐   ┌─────────────┴──────────────────────────┐
 │ 各机：secret CLI            │   │ 可选：网页端（容器）                    │
 │ 本机 age identity，私钥     │   │ 放在你的访问层后面，任意 OIDC 登录      │
 │ 不出本机                    │   │ 自己持有一把 age identity               │
 │ AI / 脚本 / 常驻服务取值    │   │ 人：浏览、显示、复制、编辑              │
 └────────────────────────────┘   └────────────────────────────────────────┘
```

- **数据仓**：每个条目一个 `.age` 文件，加密给所有允许的收件人（各设备、某个服务、一把离线恢复钥匙）。元数据是明文 TOML，**不含值**。读值不需要任何服务端，git 就是传输层。
- **条目类型**：`kv`（给脚本用的 dotenv 字段）、`file`（私钥、`.env` 文件，批准后可以落地到 `~/.ssh/…`）、`doc`（给人看的 markdown）。
- **漂移检查**：`secret check` 核对 catalog ↔ store ↔ lock 一致、收件人集合与 policy 一致、抽样解密、pre-commit 钩子，并在你的日志里扫泄露的值（只报名字）。
- **泄露应急清单**：`secret inventory` 把 catalog 元数据（`rotate`、`readers`、`priority`、`linked`）生成一页"按什么顺序、去哪里换什么"，全程不解密。

| 部分 | 是什么 | 文档 |
|---|---|---|
| `cli/` | `secret` CLI，PowerShell，Windows PowerShell 5.1 与 pwsh 7（Windows / Linux / macOS）都能跑 | [cli/README.zh-CN.md](cli/README.zh-CN.md) |
| `web/` | 网页端，ASP.NET，Docker，任意 OIDC（文档以 Google 为例） | [web/README.zh-CN.md](web/README.zh-CN.md) |
| `FORMAT.zh-CN.md` | 两边共同实现的数据格式契约 | [FORMAT.zh-CN.md](FORMAT.zh-CN.md) |
| `examples/data-repo/` | 私有数据仓的起始文件 | — |

## 快速开始（CLI）

依赖：`git`、[`age` / `age-keygen`](https://github.com/FiloSottile/age) v1.3+、PowerShell（5.1 或 7）。

```bash
# 1. 用模板建你的私有数据仓
cp -r secret-run/examples/data-repo ~/secrets && cd ~/secrets && git init && git add -A && git commit -m init
# 2. 生成本机 identity（打印公钥并登记本机）
secret-run/cli/secret init
# 3. 添加一个值，不经过 shell 历史
printf 'API_KEY=%s\n' "$(read -rs v; echo "$v")" | secret-run/cli/secret add personal/demo/api --type kv --title "Demo API" --stdin
# 4. 使用——单引号：由子进程展开 $API_KEY，不是你的 shell
secret-run/cli/secret run -e API_KEY=personal/demo/api#API_KEY -- bash -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com'
```

把 `cli/` 加进 PATH 就能直接敲 `secret`。加机器：在新机上 `secret init`（登记为 `pending`），然后在已有访问权的机器上 `secret recipients approve <名字>` 并 `secret rekey`。用 `secret recovery new` 生成离线恢复钥匙。

**告诉你的 AI**：在 AI 的指令文件（CLAUDE.md / AGENTS.md）里加一段：

> 凭据一律写指针 `secret:<路径>#<字段>`，取值只用 `secret run -e NAME=<路径>#<字段> -- <命令>`。不要用 `secret get` / `show` / `edit`，不要读 `~/.config/secrets/`，不要加 `--no-mask`。输出里出现 `<concealed:NAME>` 是正常的。

Claude Code 里再用 `permissions.deny` 挡住 Read 工具读钥匙：`"permissions": { "deny": ["Read(~/.config/secrets/**)", "Read(~/.ssh/*.pem)"] }`。

## 安全模型——用之前先看

- **一把 identity 能解开加密给它的全部条目。** 丢一台设备就要轮换它能读到的所有值。`rekey` 只影响以后的密文，git 历史里的旧密文用旧钥匙照样能解。用 `policy.toml` 收窄每个收件人能拿到的范围。
- **网页端在服务端解密。** 控制那台主机的人能读到加密给它那把 identity 的全部条目。它**必须**放在访问层（VPN、Tailscale、零信任代理……）后面——生产环境不声明访问层就拒绝启动——并且应该只给它窄范围的 policy。
- **遮罩是尽力而为。** 它拦的是手滑（调试打印、报错里的环境变量转储），拦不住有意外传的 AI：base64、`--no-mask`、把值写进文件都能绕过。真正的边界是"AI 的命令行和文件里永远拿不到值"。
- **能 push 到数据仓的人可以伪造条目**（age 不认证发件人）。落地根目录写死在代码里、新目标要你批准，但替换已批准目标的内容检测不到。见 [FORMAT.zh-CN.md §十五](FORMAT.zh-CN.md)。
- 元数据（条目名、描述、收件人）是明文。数据仓保持私有，条目命名不要带能推出值的信息。

## 同类工具

| 工具 | 重合的地方 | 区别 |
|---|---|---|
| [1Password CLI `op run`](https://developer.1password.com/docs/cli/secret-references/) | `op://` 引用、注入环境变量、输出遮罩（遮罩的灵感来源） | 商业 SaaS，不能自建 |
| [SOPS](https://github.com/getsops/sops) + age | 加密文件放 git | 面向 GitOps；没有带遮罩的 `run`，没有按条目的模型 |
| [passage](https://github.com/FiloSottile/passage)、[gage](https://github.com/distillerylabs/gage) | age + git、每个密钥一个文件 | 没有注入 / 遮罩、没有漂移检查、没有网页端 |
| [secretless-ai](https://github.com/opena2a-org/secretless-ai) | 让密钥远离 AI 工具、hook、`run` | 存储后端不同，不是 age + git |
| [Infisical](https://github.com/Infisical/infisical) | 网页端 + `infisical run`、可自建 | 带数据库的服务端，体量大得多 |

## 状态

个人工具，在几台机器上日常使用，按现状公开。欢迎 issue 和 PR，但不承诺支持。

## 许可

[MIT](LICENSE)
