# secret-run 的 Claude Code plugin

[English](README.md) | 简体中文

一个 [Claude Code](https://code.claude.com) plugin，教 AI 编程助手安全使用 [secret-run](../README.zh-CN.md)，并用一个机械护栏兜底。

## 包含什么

- **一个 skill**（`skills/use-secret-run/`）：任务需要某个凭据的值、或看到 `secret:<path>#<FIELD>` 这样的指针时加载进上下文。告诉 agent：只能通过 `secret run -e NAME=<path>#<FIELD> -- <command>` 取值；捕获输出里出现 `<concealed:NAME>` 是正常的、不要想办法绕过去看原值；永远不要跑 `get` / `show` / `edit`，也不要自己动手解密。
- **一个 PreToolUse hook**（`hooks/guard-secret-run.ps1`）：给 skill 兜底的机械护栏。即使 skill 的指令被忽略或忘了，它也会拦住会把值带进对话的那些调用：`secret get/show/edit`、`secret run` 的子命令把刚注入的值又打出来、`age -d` / `age --decrypt`、直接调 `SecretLib.ps1` 的解密函数、读 identity 或恢复钥匙文件。具体规则清单与已知缺口见脚本开头的注释。

这两样都看不见"先把脚本写到盘上、再用 `secret run -- <那个脚本>` 跑"这种形态——解析任意脚本的误伤率太高,做不到;所以即使 hook 没出声,skill 里的规则依然适用。

## 安装

在 Claude Code 终端会话里，确认这个仓（或你的 fork / 镜像）能被 git 访问到之后：

```
/plugin marketplace add ZhengchenTao/secret-run
/plugin install secret-run@secret-run
```

或者开发阶段直接挂本地目录，不走 marketplace：

```
claude --plugin-dir /path/to/secret-run/claude-plugin
```

## 依赖

hook 直接跑 `pwsh`（PowerShell 7）——跟 `secret run` 自己在所有平台上的依赖一样（见
[`cli/README.zh-CN.md`](../cli/README.zh-CN.md)）。如果 `PATH` 上找不到 `pwsh`，hook 起不来；
Claude Code 把这种情况当成不阻断的错误，工具调用照常放行（fail-open，见下一节）——这时就只剩
skill 的指令在管用了。

## 为什么选 fail-open

hook 只有在退出码 0 且输出 `deny` 决策时才拦；脚本找不到、顶层 `try/catch` 之外抛了异常、超时——
这些失败按 Claude Code 默认行为都是不阻断的，本插件也没有给这个 hook 加 `onFailure: "block"`。
一个会崩、会卡住的 hook，不该是工作会话和卡死会话之间唯一的那道闸——跟 `secret run` 自己的输出遮罩
是同一个取舍（最佳努力，不是单靠它就能当安全边界；见根 README 的
[安全模型](../README.zh-CN.md#安全模型用之前先看)一节）。想要硬拦截，自己在 `hooks/hooks.json`
里给这条 hook 加 `"onFailure": "block"`——这里故意没加。

## 测试

```
pwsh -NoProfile -File claude-plugin/test/test-guard-secret-run.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File claude-plugin/test/test-guard-secret-run.ps1
```

喂给 hook 跟 Claude Code 发出来的一样的 stdin JSON 形状，跑一组 deny/allow 用例；不碰真实数据仓、
identity 或任何值。退出码 0 = 全部通过。
