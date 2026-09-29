# secret CLI

secret-run 数据仓的命令行工具。格式契约见 [../FORMAT.zh-CN.md](../FORMAT.zh-CN.md)。English: [README.md](README.md)

- 入口：`secret.ps1`；`secret.cmd`（cmd / PowerShell）、`secret`（Git Bash / POSIX）两个 shim，优先 `pwsh`，没有就用 `powershell.exe`。
- 库：`SecretLib.ps1`（受限 TOML、kv、glob、收件人哈希、lock、age 调用、ACL），别的脚本可以 dot-source 复用。
- 源码只用 ASCII，Windows PowerShell 5.1 和 pwsh 7（Windows / Linux / macOS）都能跑。依赖 PATH 里的 `age` / `age-keygen`（v1.3+）和 `git`。
- 明文只在内存和到 age 的管道里流动；只有 `add` / `edit` 的编辑器环节会落临时文件（`%LOCALAPPDATA%\secret\tmp` 或 `~/.cache/secret/tmp`，ACL 只留本人，用完抹零删除）。

## 配合 AI 编程助手使用

设计的出发点：**值只送到需要它的进程，不进模型的上下文。**

- 文档和提示词里只写指针：`secret:<路径>#<字段>`。
- AI 跑命令一律 `secret run -e NAME=<路径>#<字段> -- <命令>`：值只存在于子进程的环境变量里。
- **输出遮罩**：`secret run` 自己的 stdout / stderr 被重定向时（AI 工具捕获输出、写日志、管道），子进程对应的流改经 `secret` 转发，注入的值（UTF-8 字节 ≥ 6）一律替换成 `<concealed:NAME>`。是控制台的流照旧继承，所以人在终端里、挂在控制台宿主下的服务都不受影响。按字节匹配，二进制输出原样透传；值跨两次写入也能拼上。**遮不住的**：子进程把值变换后再输出（base64、URL 编码）、值中间停顿超过 200 ms、短于 6 字节的值。`--mask` 强制两个流都遮，`--no-mask` 关掉。它防手滑，不防有意绕行。
- 告诉你的 AI 不要用 `get` / `show` / `edit`、不要读 `~/.config/secrets/`。Claude Code 里可以加 `permissions.deny`，如 `Read(~/.config/secrets/**)`、`Read(~/.ssh/*.pem)`。

## 全局选项与环境变量

| 项 | 说明 |
|---|---|
| `--repo <dir>` / `SECRET_REPO` | 数据仓。默认：设了 `SECRET_WORKSPACE` 时是 `{workspace}/secrets`，否则 `~/secrets` |
| `--identity <file>` / `SECRET_IDENTITY` | 本机 identity，默认 `~/.config/secrets/identity.txt`（Windows 的 `~` 取 `USERPROFILE`） |
| `--pull` | 执行前先 `git pull --ff-only` |
| `SECRET_WORKSPACE` | `{workspace}/` 落地目标的根目录。不设 = 这类目标一律拒绝 |
| `SECRET_SCAN_LOGS` | `check` 额外扫描泄露的日志文件（用平台的路径分隔符隔开） |
| `SECRET_INVENTORY_TEMPLATE` | `inventory` 用的模板，例如自带的 `inventory-template.zh-CN.md` |
| `SECRET_HOME` / `SECRET_STATE_DIR` / `SECRET_DESKTOP` / `SECRET_DEVICE_NAME` | **只给自测用**：分别覆盖家目录、`%LOCALAPPDATA%\secret`、桌面目录和本机设备名 |

## 注意事项

- **编辑器必须阻塞**：`secret` 等编辑器进程退出后才读回文件。VS Code 要写成 `EDITOR="code --wait"`；不设置时 Windows 默认用 `%SystemRoot%\System32\notepad.exe`。编辑器的备份、swap、自动恢复功能要关掉（例如 vim 用 `vim -n` 并设置 `nobackup nowritebackup`），否则明文会留在临时目录之外。kv 内容不合法时会询问是否重新打开编辑器（内容保留）；stdin 已经结束时直接放弃，什么都不写。
- **别的 PowerShell 脚本取值**：dot-source `SecretLib.ps1`，调 `Sec-GetField <repo> <identity> <path> <FIELD>`（字符串）或 `Sec-GetEntryBytes <repo> <identity> <path>`（字节），或者用默认仓与 identity 的 `Sec-ReadField <path> <FIELD>`。在 PowerShell 里捕获子进程 `secret get` 的输出前，先设 `[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)`。
- **退出码**：直接调用或经 shim 调用时可靠。计划任务用 `conhost --headless … secret run …` 包装服务时，conhost 会吞掉退出码，保活只能看进程是否还活着。
- **写入的原子性**：`add` / `edit` / `rekey` 先把新内容全部写成临时文件，全部成功后才按"密文 → lock → catalog"的顺序替换；任何一步失败都用内存里的旧字节回滚。lock 里的密文哈希与文件对不上（有人绕过 CLI 改过）时，这三个命令都拒绝覆盖。
- **落地目标的安全检查**：从根目录到父目录的每一级、以及目标文件本身，只要是 junction 或 symlink 就拒绝；Windows 保留名段一律拒绝（包括带扩展名的，如 `nul.txt`）。脚本和可执行文件（`.ps1` `.psm1` `.cmd` `.bat` `.exe` `.dll` `.js` `.vbs`）、`~/.ssh/config*`、`authorized_keys` 作为目标时，批准前会标出 `SENSITIVE`。
- **应急清单的四个键**（FORMAT §六）：`rotate`（在哪轮换）、`readers`（谁在读）、`priority`（`high` / `normal` / `low`，**只决定处置顺序，没有加密含义**）、`linked`（要一起换的条目）。`secret add` 对应 `--rotate '<说明>'`、`--reader '<读取方>'`（可重复）、`--priority high`、`--linked <path>`（可重复）。这些键都不写值、不写带账号的 URL。
- **catalog 的键序写死**（FORMAT §六），不认识的键原样保留、排在 `updated` 之后。CLI 和网页写出的字节相同，交替写入不会产生整表 diff。
- **`secret rm` 不碰已落地的文件，也不改写 git 历史**：落地文件自己删，值该换还得换。
- **catalog 里有不合法条目**：`check` 报 `ERROR catalog-entry`。只读命令（get / show / run / list / resolve 等）跳过它们，其余条目照常可用；写命令（add / edit / rekey 等）要求先修好。报错里会列出每个无效条目和它违反的约束；在 `catalog.toml` 里改正（或连同密文和 lock 行一起删掉那个 `[[entry]]` 块），再跑 `secret check`。

会写仓的命令（`init` / `recipients add|approve|remove` / `rekey` / `add` / `edit` / `rm` / `recovery new|seal|confirm` / `inventory` 写文件时）：

- **默认就提交**，消息自动生成（`secret: add personal/x/y (kv)`、`secret: rm …`、`secret: rekey N entries`）。`--commit "<msg>"` 换消息，`--no-commit` 只暂存。
- **提交只包含本次动过的文件**（`git commit -- <这些文件>`），工作区里别的改动不会被扫进来。有与本次无关的未提交改动（catalog / policy / recipients / store / INCIDENT.md）时打一条 WARN 列出文件名，不阻断。
- **落后 upstream** 时 WARN 一行（提示先 `--pull` 或 `git pull --rebase`），不阻断。
- `--push` 始终要显式加。推送被拒（远端有新提交）时**不会自动 rebase**，只报错并告诉你：先 `git -C <仓> pull --rebase`，再 `git push`，然后 `secret check`。
- **每台机一把写锁**：仓外（`%LOCALAPPDATA%\secret\locks\` / `~/.cache/secret/locks/`）一把独占文件锁，默认等 30 秒（`--lock-timeout <秒>`，0 = 不等）；拿不到就报错并给出持锁进程的 pid 和命令名。只读命令不取锁。进程被杀时锁自动释放。

## 命令

| 命令 | 作用 |
|---|---|
| `secret init [--name <n>]` | 没有 identity 就生成一个（已有不覆盖），打印公钥；把本机登记进 `recipients.toml`：仓里还没有 active 收件人或 store 为空时登记为 `active`，否则 `pending` |
| `secret recipients list` | 列出收件人 |
| `secret recipients add <name> <key> [--type device\|service\|recovery] [--pending]` | 登记收件人（默认 active） |
| `secret recipients approve <name>` / `remove <name>` | pending → active / 改成 revoked（保留记录）；做完要 `rekey` |
| `secret rekey [--all]` | 重新加密收件人集合哈希与 policy 不一致的密文（`--all` 重加密全部），替换前先核对明文 SHA-256，并更新 lock。任何一条失败（包括 lock 哈希对不上）就整体放弃 |
| `secret add <path> --type kv\|file\|doc --title <t> [--description <d>] [--from-file <f> \| --stdin] [--target <t>] [--acl private\|inherit] [--machines a,b] [--tag x]... [--alias x]... [--replace]` | 新增条目；不给输入源就打开 `$EDITOR`。kv 严格校验，`fields` 按内容里的键顺序生成 |
| `secret edit <path>` | 解密到临时文件后打开编辑器，内容变了才重新加密，同时更新 `updated`、kv 的 `fields` 和 lock |
| `secret rm <path> [--yes] [--force] [--keep-target]` | 删除条目：密文、catalog 条目、lock 行三者一起删（失败全回滚）。不加 `--yes` 只打印摘要（含 `readers` 与 `linked`）并以退出码 2 结束。**别的条目在 `linked` 里引用它时默认拒绝**（退出码 1，列出引用方），`--force` 才删，并在同一个事务里摘掉引用方的这一项。已落地的文件**不会**被删。密文仍在 git 历史里，值该换还得换 |
| `secret inventory [--out <file>] [--stdout]` | 从 catalog 生成泄露应急清单（markdown，**不含值**），按 domain/group 分组、按 `priority` 再按 path 排序，默认写 `<仓>/INCIDENT.md`。`check` 会在内存里重新生成一份比对，文件缺失或过期就 WARN。写之前用本机能解密的 kv 值在输出里做一次子串自检：值在 catalog 文本里只出现一次（有人把凭据粘进了标题 / 描述）就报条目名和字段名并拒绝写入；出现 2 次以上（用户名 / 库名 / 环境名这类标识符型的值）只打一行 note。短于 4 字符的值跳过 |
| `secret show <path>` | 给人看：kv 显示 `KEY=VALUE`，doc 显示原文，file 是 UTF-8 文本就显示，否则只显示大小和 SHA-256 |
| `secret get <path>#<FIELD>` | 把值原样写到 stdout，不加换行（给脚本用） |
| `secret get <path> --out <file> [--allow-sync-dir]` | 把整个条目写到文件（ACL 只留本人；目标已存在时拒绝）。路径按落地规则校验：数据仓内部、junction / symlink、保留名一律拒绝；云同步目录（OneDrive / Dropbox / Google Drive / iCloudDrive / Nextcloud / Syncthing）默认拒绝，`--allow-sync-dir` 才写 |
| `secret run [-e NAME=<path>#<FIELD>]... [-a [PREFIX=]<path>]... [--mask\|--no-mask] -- <cmd> [args]` | 只把值注入子进程的环境变量，返回子进程退出码；输出遮罩见上文。`.ps1` 用当前宿主执行，`.cmd` / `.bat` 经 `cmd.exe /c` 执行 |
| `secret materialize [--approve] [--force] [--dry-run] [<path>...]` | 把 file 条目落地到 `target`（只允许 `~/.ssh/`、`{workspace}/`）。首次落地的 `(path, target)` 组合要加 `--approve`，批准记录在 `%LOCALAPPDATA%\secret\approved-targets.txt`。输出标记：`+` 已写入 / `=` 相同 / `!` 不同，已跳过（`--force` 覆盖）/ `?` 未批准 / `X` 出错 |
| `secret list [<prefix>]` / `secret info <path>` | 只读 catalog，不解密 |
| `secret resolve <旧指针>` | 通过条目的 `aliases`，把旧指针（如 `notes:ops/chat-bot.md#凭据`）解析成 `secret:<path>` |
| `secret check [--sample <n>] [--web <url>] [--scan-log <path>]... [--no-log-scan] [--quick]` | 按 FORMAT §十二 做全部检查，每行 `<级别> <检查项> <名字>`；退出码 0 / 2（有 WARN）/ 1（有 ERROR）。另外：`hooks` 核对数据仓的 `core.hooksPath` 是否指向 `cli/githooks`（不一致是 ERROR，提示跑 `secret hooks install`）；`log-leak` 在日志（`%LOCALAPPDATA%\secret\*.log`、`SECRET_SCAN_LOGS`、`--scan-log`）里扫条目的值，命中输出 `ERROR log-leak <日志文件名> <条目#字段>`，**只报名字不报值**。阈值：kv 值短于 4 字符跳过；file 条目只取"像单行凭据"的行（≥ 12 字符、无空白）；路径以 `-pub` 结尾的条目跳过。扫描全绿只代表「没扫到」，不等于没泄露。`git` 项对比 HEAD 与缓存的 `@{u}`，从不 fetch（离线也不报错），领先或落后时 WARN |
| `secret recovery new [--out <file>] [--replace]` | 生成恢复 identity（默认写到桌面，不显示私钥），登记为 active 的 `recovery` 收件人 |
| `secret recovery drill --identity <恢复钥匙> [<path>]` | 只用恢复钥匙解开一个条目，和本机解出的结果比较，输出 `match true\|false` |
| `secret recovery seal --identity <恢复钥匙> [--replace]` | 交互运行 `age -p`，生成 `recovery/recovery-identity.age`（口令由人输入） |
| `secret recovery confirm` | 桌面上已经没有恢复钥匙文件后，写入 `backup = "offline <日期>"` |
| `secret hooks install` | 把数据仓的 `core.hooksPath` 指向 `cli/githooks/`（pre-commit 校验 `.age` 文件头、路径和白名单） |

## 自测

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cli/test/selftest.ps1
pwsh -NoProfile -File cli/test/selftest.ps1
```

只使用临时目录里的测试仓、测试 identity 和随机测试值，跑完自动清理；全部通过时退出码为 0。
