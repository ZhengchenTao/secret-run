# FORMAT —— secret-run 数据仓格式契约（v1）

> 这是 `secret` CLI（`cli/`，PowerShell）和网页端（`web/`，.NET）**共同遵守的唯一契约**。任何一方想改格式，先改本文、升 `catalog.toml` 里 `[[meta]]` 的 `format`，再改实现。
> 一句话：**纯 age 文件 + 受限 TOML**，两边都不做自定义加密或封装。
> English: [FORMAT.md](FORMAT.md)（两份内容一致，有出入以英文版为准）

## 一、仓目录

```
FORMAT.md                可选：本文的副本
README.md                人类入口
INCIDENT.md              泄露应急清单：由 `secret inventory` 从 catalog 生成（条目名 / 在哪轮换 / 谁在读，不含值，不手改）
recipients.toml          收件人（公钥，非机密）
policy.toml              路径规则 → 收件人
catalog.toml             条目元数据（明文，不含值）
store/
  .recipients.lock       每个密文最后一次加密时的收件人集合哈希 + 密文哈希（CLI 写）
  <domain>/<group>/<name>.<type>.age
recovery/
  recovery-identity.age  可选：恢复钥匙用口令（scrypt）加密的副本，由 `secret recovery seal` 生成
.gitattributes           *.age binary
.gitignore               逐个点名的白名单，拦截一切明文落进工作区
```

- 仓保持 **private**，不要喂给搜索索引或 AI 知识库。
- 除 `store/**/*.age` 与 `recovery/*.age` 外，仓里**所有文件都是明文**，能读到仓就能读到它们 —— 所以里面**不能出现值，也不能出现能推出值的信息**（token 前缀、密码长度、"和 xx 账号同密码"、恢复钥匙存在哪）。

## 二、编码与通用约定

| 项 | 约定 |
|---|---|
| 文本编码 | UTF-8，**无 BOM**，行尾 LF（写入方必须保证；读取方容忍 CRLF 与开头的 BOM） |
| Unicode | 所有明文元数据（toml 里的字符串、别名）写入前规范化为 **NFC**；比较前两边都做 NFC |
| 仓内路径 | 正斜杠，相对仓根，大小写敏感 |
| 哈希 | SHA-256，小写 hex |
| 日期 | `YYYY-MM-DD` |
| 排序 / 去重 | 一律**序数比较**：按 UTF-8 字节逐字节、区分大小写。PowerShell 必须显式用 `[StringComparer]::Ordinal`（`Sort-Object` / `-Unique` 默认按区域且不分大小写，不能用）；.NET 用 `StringComparer.Ordinal`。本仓排序的对象（`age1…` 公钥、`store/…` 路径）都是 ASCII，UTF-16 序数与 UTF-8 字节序结果相同 |
| age | 二进制格式（不用 `-a` armor）；只用 X25519 收件人；恢复副本例外用 scrypt 口令 |

## 三、受限 TOML

四个 toml 只用 TOML 1.0 的一个子集。**写入方只能产出这个子集；读取方遇到子集之外的语法必须报错，不许猜。** PowerShell 侧手写解析器；.NET 侧可以用标准 TOML 库，但**解析后必须再校验一遍**：顶层只有表数组、值只有字符串 / 字符串数组 / 布尔（标准库会接受整数、内联表、点号键等子集外语法）。

- 顶层**只有表数组** `[[name]]`（不用 `[table]`、不用点号键、不用内联表 `{}`）。表数组之前可以有注释行和空行。
- 键值对：`key = value`，`=` 两侧允许任意个空格或制表符。键是裸键 `^[A-Za-z0-9_-]+$`；同一个块内键不重复。
- 值只有四种：
  - 基本字符串 `"…"`：转义只支持 `\"` `\\` `\n` `\t` `\r` `\uXXXX`（`XXXX` 不能落在代理对范围 `D800–DFFF`）；其他反斜杠序列报错
  - 字面字符串 `'…'`（无转义，不能含 `'`）
  - 字符串数组 `["a", "b"]`，允许跨行、允许末尾逗号、允许空数组 `[]`，元素只能是上面两种字符串
  - 布尔 `true` / `false`
- 两种字符串里都**不允许控制字符**（U+0000–U+001F、U+007F；制表符也不行，要用 `\t`）。转义解出来的控制字符（`\u0000`–`\u001F`、`\u007F`）同样非法，只有 `\t` `\n` `\r` 三个转义例外。
- 注释 `#` 到行尾（字符串内部的 `#` 不算）。
- 没有整数、浮点、日期类型（日期写成字符串）。
- 未知键：读取方**忽略**（向前兼容）；未知表数组名：忽略。

CLI 重写 toml 时按规范形态输出：块之间空一行，键按本文表格里的顺序，字符串一律用基本字符串、只转义必须转义的字符；文件开头连续的注释行原样保留，块内注释不保证保留。

## 四、`recipients.toml`

```toml
# 收件人：公钥是公开信息。私钥位置见 §九。
[[recipient]]
name = "laptop"
type = "device"
key = "age1…"
status = "active"
added = "2026-01-01"

[[recipient]]
name = "recovery"
type = "recovery"
key = "age1…"
status = "active"
added = "2026-01-01"
backup = ""
```

| 键 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 匹配 §六 的路径段正则，全局唯一。设备默认取小写的计算机名（`secret init` 自动取，`--name` 可改）；网页端等服务用自己的名字（如 `web`）；恢复钥匙固定 `recovery` |
| `type` | 是 | `device` / `service` / `recovery` |
| `key` | 是 | X25519 公钥，**必须匹配 `^age1[02-9ac-hj-np-z]{58}$`**（bech32 小写；大写或混写一律拒绝，否则同一把钥匙会算出不同哈希） |
| `status` | 是 | `active`（参与加密）/ `pending`（已登记、等批准，**不参与加密**）/ `revoked`（保留记录，不参与加密） |
| `added` | 是 | 登记日期 |
| `backup` | 仅 recovery | 确认恢复钥匙已离线保存后写成 `"offline <日期>"`（**不写存在哪**）；为空或缺失时 `secret check` 持续 WARN |
| `note` | 否 | 备注（明文，不写敏感信息） |

- 同一个 `key` 不能出现在两条记录里（ERROR）。
- **收件人组**是隐式的，不单独声明：`@all` = 全部 `active`；`@device` / `@service` / `@recovery` = 该类型的全部 `active`。

## 五、`policy.toml`

```toml
[[rule]]
path = "store/**"
recipients = ["@all"]
```

- `recipients`：收件人名或组（`@…`）的数组，展开成公钥集合后去重。引用了不存在或非 `active` 的名字 → 该名字忽略，`check` 报 WARN。
- **最后一条匹配的规则生效**（不合并）。没有任何规则匹配的密文 = ERROR。
- 展开结果为**空集** = ERROR（这样的文件无法加密，也不许写）；展开结果**不含任何 `recovery` 类型**的收件人 = WARN。
- 用更多规则收窄谁能读什么——例如网页端（`type = "service"`）只给它需要展示的条目，网页主机被攻破时不至于全部泄露。

**glob 语义**（不是 gitignore 风格）：`path` 对密文的仓内完整路径（如 `store/personal/ssh/deploy-key.file.age`）**整串锚定**匹配。翻译成正则：`**` → `.*`，`*` → `[^/]*`，`?` → `[^/]`，其余字符按字面转义；首尾加 `^` `$`。没有字符类，`**/` **不**匹配零段。

| pattern | 路径 | 结果 |
|---|---|---|
| `store/**` | `store/personal/ssh/a.file.age` | 匹配 |
| `store/personal/*` | `store/personal/ssh/a.file.age` | 不匹配（`*` 不跨 `/`） |
| `store/**/a.file.age` | `store/personal/ssh/a.file.age` | 匹配 |
| `store/**/x.kv.age` | `store/x.kv.age` | 不匹配（`**/` 不匹配零段） |

**收件人集合哈希**（lock 与 check 共用的算法）：把规则展开后的公钥字符串去重、按序数升序排序、用 `\n` 连接（末尾不加换行），取 UTF-8 字节的 SHA-256。

## 六、`catalog.toml`

```toml
[[meta]]
format = "1"

[[entry]]
path = "work/chat/bot-app"
type = "kv"
title = "聊天机器人应用凭据"
description = "通知脚本与聊天 MCP 服务用的 App ID / App Secret"
fields = ["APP_ID", "APP_SECRET"]
tags = ["chat"]
rotate = "开发者后台 → 应用 → 凭证 → 重置 Secret"
readers = ["tools/notify.ps1", "聊天 MCP 服务"]
aliases = ["notes:ops/chat-bot.md#凭据"]
updated = "2026-01-01"

[[entry]]
path = "personal/ssh/prod-server-pem"
type = "file"
title = "生产服务器私钥"
description = "…"
target = "~/.ssh/prod_server.pem"
acl = "private"
updated = "2026-01-01"
```

- **取值约束（CLI 与网页判定必须一致）**：`path`、`type`、`title`、`updated` 是非空字符串；`updated` / `added` 必须是真实存在的日历日期（ASCII 数字 `YYYY-MM-DD`，`2026-02-30` 非法）；kv 的 `fields` 非空；`tags` 元素非空；别名规范化后路径部分非空；`target` 语法检查（开头、段规则、保留名）两边完全相同——网页不做落地但同样校验。违反任一条 = 该条目 ERROR：CLI `check` 报 ERROR，网页只把该条目标为不可用，**不让整站不可用**（整站不可用只限 toml 解析失败、`[[meta]]` 缺失或 `format` 不认识）。
- `catalog.toml` 第一个块固定是 `[[meta]]`，只有一个键 `format = "1"`（字符串）。读取方遇到缺失或不认识的 `format` 必须拒绝工作。

| 键 | 必填 | 说明 |
|---|---|---|
| `path` | 是 | 逻辑路径 `<domain>/<group>/<name>`，**恰好三段**。每段（包括 domain，自己取，如 `personal`、`work`、`client-a`）匹配 `^[a-z0-9][a-z0-9-]*$` 且**不是** Windows 保留名（`con` `prn` `aux` `nul` `com1`–`com9` `lpt1`–`lpt9`）。全局唯一 |
| `type` | 是 | `kv` / `file` / `doc`，见 §七 |
| `title` | 是 | 人看的标题（任意语言） |
| `description` | 否 | 用途、谁在读；**不含值** |
| `fields` | kv 必填 | 字段名数组（每个匹配 §七 的键正则、不重复），顺序即显示顺序；必须与密文里的键集合完全一致（`check` 解密抽样时核对，只比名字） |
| `target` | 否（仅 file） | `materialize` 的落地路径，见下「落地目标」 |
| `acl` | 否（仅 file） | `private`（默认：Windows 断继承、只授当前用户完全控制；POSIX `0600`）/ `inherit`（跟随目录，如 `.pub`） |
| `machines` | 否（仅 file） | 只在这些设备上 materialize，元素必须是 `device` 类型的收件人名；缺省 = 所有能解密它的设备 |
| `tags` | 否 | 搜索用标签 |
| `rotate` | 否 | **泄露应急清单用**：在哪里换这个值，写控制台 / 系统名，如 `"开发者后台 → Bot → Reset Token"`、`"重新生成密钥对并推 authorized_keys"`。**不写 URL 里的账号、不写值** |
| `readers` | 否 | 泄露应急清单用：谁在读它（脚本 / 服务 / 人）。用于评估"换了值要同步改哪里" |
| `priority` | 否 | 泄露应急清单的**处置顺序**：`high` / `normal`（默认）/ `low`。**纯排序用，没有任何加密含义** |
| `linked` | 否 | 联动条目：换这个必须一起换的其他条目路径数组（如 deploy key 与 known_hosts、token 与 CI secret）。元素必须是存在的条目 path |
| `aliases` | 否 | 旧指针，格式见 §八 |
| `updated` | 是 | 最后一次改内容的日期（CLI 写） |

- 条目文件 = `store/<path>.<type>.age`。catalog 与 store 必须一一对应：有条目没文件、有文件没条目都是 `check` ERROR。
- **命名规则**：路径、标题、描述、标签都只描述"这是什么、给谁用"，**不带值，也不带能推出值的东西**。
- **键序（写出时必须一致）**：`path`、`type`、`title`、`description`、`fields`、`target`、`acl`、`machines`、`tags`、`rotate`、`readers`、`priority`、`linked`、`aliases`、`updated`；**本实现不认识的键原样保留、排在 `updated` 之后**，彼此相对顺序不变。两个实现对同一份内容写出的字节必须完全相同（各自都要有这条回归测试）——否则 CLI 与网页交替写入会产生整表 diff。
- **`linked` 是双向约束**：删除某条目前要检查"谁 linked 了它"，不能留下指向不存在条目的引用（会让引用方条目失效，网页也会因此整体拒绝写入）。

**落地目标（`target`）**

- 只允许两种开头：`~/`（用户家目录；Windows 取 `USERPROFILE`，**不取 `HOME`**——Git Bash 会改写它）或 `{workspace}/`（环境变量 `SECRET_WORKSPACE` 指定的目录；**没设时 `{workspace}/` 目标一律拒绝**）。占位符只能出现在开头；其余位置出现 `{` `}`、出现 `..` 段、`.` 段、空段、反斜杠、任意位置的冒号（含驱动器号）、控制字符、以 `.` 或空格结尾的段、Windows 保留名段（含带扩展名的，如 `nul.txt`、`COM1.log`，不区分大小写）→ 非法（ERROR，不落地）。CLI 落地时另外逐级拒绝 reparse point（junction / symlink）。
- **落地根目录白名单写死在 CLI 代码里，不放在数据仓**：`~/.ssh/`、`{workspace}/`。仓里的 `target` 只能在白名单之内选路径。
- **首次落地或 `target` 变了要人确认**：CLI 在本机（仓外）记住已批准的 `(条目 path, target)` 组合；遇到没批准过的组合，`materialize` 只列出来并跳过，加 `--approve` 才写。原因见 §十五 威胁模型第 1 条。

## 七、三种条目类型（密文里的明文长什么样）

| type | 明文格式 | 用途 |
|---|---|---|
| `kv` | dotenv 子集，见下 | 脚本 / 服务取值（`secret run` / `secret get`） |
| `file` | 任意字节，原样 | 落地到本机某个路径（ssh 私钥、`.env`、带凭据的脚本） |
| `doc` | UTF-8 markdown | 人看；网页渲染 |

**`kv` 的 dotenv 子集**：

```
# 注释行（整行以 # 开头）会被忽略
APP_ID=value-to-end-of-line
APP_SECRET=value-to-end-of-line
```

- 按 `\n` 分行；每行末尾**最多去掉一个** `\r`。之后：空行、`#` 开头的行忽略；其余每行必须是 `KEY=VALUE`。
- `KEY` 匹配 `^[A-Z][A-Z0-9_]*$`，键不重复。第一个 `=` 之后到行尾全部是值，**不去引号、不处理转义、不去首尾空格**。`KEY=`（空值）合法。
- 任何不合法的行（小写键、前导空格、`export K=…`、没有 `=`）→ **整个条目解析失败**（报错，不跳过）。
- 值不能含 `\r`、`\n`、NUL；写入方遇到这种值必须拒绝（需要多行的东西用 `file`）。
- 写入方：UTF-8 无 BOM、LF、每行以 `\n` 结尾。

**字段引用语法**（文档里的指针、CLI 参数通用）：`secret:<path>#<FIELD>`（kv 的一个字段）或 `secret:<path>`（整个条目）。以**最后一个** `#` 切分。CLI 参数里 `secret:` 前缀可省略。

**密文合法性**（CLI 写入后自检、`check` 与网页读取时校验）：每个 `.age` 文件必须以字节串 `age-encryption.org/v1\n` 开头；仓内路径必须匹配
`^store/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*\.(kv|file|doc)\.age$`（外加保留名排除）。不满足 = ERROR。

## 八、旧指针别名

从笔记 / wiki / 旧文件迁移时有用：`aliases` 里每一项是 `<来源>:<相对路径>[#<锚点>]`，`<来源>` 自己取名，匹配 `^[a-z][a-z0-9-]*$`（如 `wiki`、`notes`、`oldrepo`、`ssh`）。

- **规范化**（存入与比较两边都做）：去首尾空白、去外层 `[[` `]]`、反斜杠换正斜杠、NFC、以最后一个 `#` 切出锚点、路径部分去掉 `.md` 后缀。**区分大小写**。
- 必须带来源前缀，路径部分非空。
- 规范化后的别名（含锚点）**全局唯一**，重复 = ERROR。
- `secret resolve <旧指针>`：先精确匹配（含锚点）；没有再按去掉锚点的部分匹配（可能多条，全部列出）。输入必须带来源前缀。只输出 `secret:<path>`，不解密。

## 九、钥匙（identity）

| 谁 | 私钥在哪 | 说明 |
|---|---|---|
| 设备 | `~/.config/secrets/identity.txt`（Windows 下 `~` = `USERPROFILE`） | `age-keygen` 格式。Windows 断继承只留当前用户；POSIX `0600`。`secret init` 生成，私钥不离开本机 |
| 服务（如网页端） | 只在该服务的主机上，只有服务用户可读 | 不进任何仓 |
| `recovery` | 离线保存（自理）；可选 `recovery/recovery-identity.age`（口令加密） | 生成时写到桌面，存好后删除 |

- 环境变量覆盖：`SECRET_REPO`（仓根；设了 `SECRET_WORKSPACE` 时默认 `{workspace}/secrets`，否则 `~/secrets`）、`SECRET_IDENTITY`（identity 文件）。
- 私钥**不进任何仓、不进日志、不进 stdout**；只有 `age-keygen -y` 算出来的公钥可以打印。

## 十、`store/.recipients.lock`

```
# secret recipients lock v1
<收件人集合哈希>  <密文 SHA-256>  store/personal/ssh/deploy-key.file.age
```

- 第一行必须是 `# secret recipients lock v1`；之后每个密文一行，三列用**两个空格**分隔，按路径序数升序排序；不允许空行；文件以 `\n` 结尾。
- **只覆盖 `store/**` 下的密文**；`recovery/*.age` 不进 lock（它是口令加密，没有收件人）。
- 密文哈希 = 工作区里该文件的原始字节（在 `binary` 属性下与 git blob 内容一致；网页读裸仓时对 blob 内容算，结果相同）。
- 由写密文的一方（CLI 的 add / edit / rekey，网页的新增 / 编辑）在**同一个 commit** 里更新。
- `check` 判定：
  - 收件人集合哈希 ≠ policy 现算 → **需要 rekey**（ERROR）；
  - 密文哈希 ≠ 文件实际哈希 → 密文被绕过 CLI 改过，lock 不可信（ERROR）；
  - store 里有密文而 lock 里没有、或反过来 → ERROR。
- 为什么需要它：age 文件头不记录收件人公钥，从密文看不出它加密给了谁。lock **不防篡改**（能改密文的人也能改 lock），只防手滑与漂移，见 §十五。

## 十一、`.gitignore` 与明文纪律

- 仓里**永远不出现明文值**：`.gitignore` 先 `*` 全部忽略，再**逐个点名**放行：`/FORMAT.md`、`/README.md`、`/INCIDENT.md`、`/recipients.toml`、`/policy.toml`、`/catalog.toml`、`/store/**/*.age`、`/store/.recipients.lock`、`/recovery/*.age`、`.gitattributes`、`.gitignore`。新增仓根文件要同时改 `.gitignore`。
- `.age` 后缀会被放行，所以 §七「密文合法性」的文件头检查是第二道闸：CLI 装的 git pre-commit 钩子（`secret hooks install` 把 `core.hooksPath` 指向你那份 secret-run 的 `cli/githooks/`，**不放在数据仓里**，避免仓内容变成本机执行的代码）对暂存区里每个 `.age` 校验文件头和路径正则，不合法就拒绝提交。
- CLI 需要临时明文（只有 `edit` / `add` 的编辑器环节）一律放在仓外 `%LOCALAPPDATA%\secret\tmp`（POSIX `~/.cache/secret/tmp`，0700），用完即删。

## 十二、`secret check` 的状态与退出码（CLI 与网页 `/health` 共用口径）

| 级别 | 含义 | 退出码影响 |
|---|---|---|
| `OK` | 通过 | — |
| `WARN` | 要人处理但不影响取值（恢复钥匙未确认备份、policy 引用了非 active 名字、policy 结果不含 recovery、本地有未推送提交、落后远端、有待批准的落地目标） | 退出码 2（没有 ERROR 时） |
| `ERROR` | 取值会失败或存在安全问题（本机 identity 缺失 / 不在 active 收件人里、lock 不一致、catalog 与 store 不一致、密文不合法、抽样解不开、kv 字段名与 catalog 不符、已落地文件与仓不一致、别名重复、toml 不合法、扫描的日志里出现了值） | 退出码 1 |

输出每行 `<级别> <检查项> <名字或说明>`，**只输出名字和状态，不输出值**。

## 十三、网页端读取数据仓的方式

- 只读挂载裸仓；在 `HEAD` 上用 `git ls-tree` / `git cat-file` 读 toml 与密文，密文经 stdin 交给 `age -d -i <服务 identity>`，明文只在内存里。
- 列表 / 搜索只用 `catalog.toml`，不解密；`kv` 每次只解出被点的那个字段返回。
- 写入走它自己的工作区 clone 和 deploy key（`git push`），catalog / store / lock 规则与 CLI 相同。
- `/health` 返回 HEAD commit 与 `catalog.toml` 里 `[[meta]]` 的 `format`。

## 十四、版本

| 版本 | 变化 |
|---|---|
| v1 | 首版。catalog 的可选键 `rotate` / `readers` / `priority` / `linked` 属于 v1（老实现按"未知键忽略"照常工作） |

## 十五、威胁模型（格式层面，已接受的代价）

1. **能 push 到数据仓的人可以伪造条目**：age 不认证发件人，公钥又是公开的。攻击者（git 服务器被攻破、网页写入被滥用）可以造一个加密给 `@all` 的 `file` 条目并改 lock。对策：落地根目录白名单写死在 CLI、新 `(path, target)` 组合要人批准（§六）。**没防住的**：替换已批准 `target` 的内容（例如换掉 `~/.ssh/` 下某个私钥或 `{workspace}` 下某个带凭据的脚本）、替换 `kv` 值（让脚本拿错误的凭据发请求）。要彻底防需要 commit 签名校验。
2. **能读到仓的人**看得到全部元数据（条目名、描述、落地路径、收件人名单），看不到值。
3. **任一收件人私钥泄露** = 该收件人能解的全部条目泄露，且 git 历史里的旧密文照样能解；rekey 不等于撤销，必须轮换值。
4. **服务端读取方（网页端）在服务器上持有一把 identity**：控制那台服务器的人能读到加密给这把钥匙的全部条目。放在访问层（VPN、零信任代理等）后面，并用 policy 收窄它能解的范围（§五）。
