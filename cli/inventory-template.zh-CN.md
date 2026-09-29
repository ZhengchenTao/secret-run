@not-registered=未登记
@none=无
@all-machines=全部设备
@group-heading=## {0}
@table-header=| 优先级 | 条目路径 | 类型 | 标题 | 在哪轮换 | 谁在读 | 适用机器 | 落地路径 | 联动条目 | 上次更新 | 旧指针别名 |
@table-sep=|---|---|---|---|---|---|---|---|---|---|---|
@preamble
# 泄露应急清单

> 本文件由 `secret inventory` 从 `catalog.toml` 生成，**不解密、不含任何值**。改内容请改 catalog（`secret add --rotate/--reader`），不要手改本文件。

怀疑某台设备、某个服务端（如网页端）或某个凭据泄露时，**按下面的顺序逐条处理**（一把设备钥匙能解全部条目，所以泄露一台设备等于全部条目都要评估）：

0. **设备或服务端丢了 / 被拿下**：先 `secret recipients remove <名字>`，再 `secret rekey`，然后按下面逐条换值。**`rekey` 只是让新密文不再加密给它，撤销不了已经泄露的值**——git 历史里的旧密文，那把钥匙照样解得开。
1. **在控制台换值，并作废旧值**：按「在哪轮换」一列生成新值；**生成新值不等于旧值失效**，还要主动作废：从 `authorized_keys` 摘掉旧公钥、在控制台 revoke 旧 token / 撤销 OAuth 授权 / 删掉旧 App Secret、数据库账号改密码后确认旧密码登不上。
2. **写回本库**：`secret edit <条目路径>`（或 `secret add <条目路径> --replace --from-file <文件>`），然后 commit + push。「联动条目」一列里的条目要一起换。
3. **重启读取方**：按「谁在读」一列，重启用到它的服务、重跑脚本；落地文件用 `secret materialize --force` 覆盖。
4. **核对**：`secret check` 全绿；用到该凭据的功能实际跑一次。

按「优先级」一列从上到下处理：`high` 先换，`low` 可以最后。

注意：`rekey` 只换加密的收件人，**不撤销已经泄露的值**，git 历史里的旧密文照样能被旧钥匙解开——真正的补救只有换值。
@end
