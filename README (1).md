# ZCrypto V6 — MegaETH 合约（下注 + 链上结算镜像）

对应《ZCrypto V6 重构设计方案》第三节。两个合约全部 **permissionless 分步推进**，
Relay/Keeper/任何用户都只是触发者，无法影响计算结果。

## 文件

| 文件 | 说明 |
|---|---|
| `src/MerkleBuilder.sol` | 分步 Merkle Root 构建器（sorted-pair，与 V5 BetRoot 约定一致），两个合约共用 |
| `src/GuessBetV6.sol` | 逐单下注合约：双签名验签、0–5 份限额、时间窗、(user,nonce) 去重、BetRoot 构建 |
| `src/GuessSettleV6.sol` | 结算镜像合约：Chainlink 取价、diff/分组/派奖链上计算、SettlementRoot、CCIP 双消息、流局 |

已用 solc 0.8.24（optimizer 200 runs）编译通过，无错误无警告。

## 每轮时序（10 分钟格点）

```
00:00  startRound(rid)                    开局（格点开始 2 分钟宽限内）
00:00~05:00  bet(...)                     逐单实时上链（Relay 转发或用户直连）
05:00  closeRound(rid, n) × 若干次         关窗 + 生成叶子层
       buildBetRoot(rid, n) × 若干次       分步构建 BetRoot → state=Closed
       beginRound(rid)                    结算合约绑定轮次
       requestVrf(rid)                    （达门槛且非强制决胜位时）
10:00  anchorPrice(rid, oracleRoundId)    锚定 priceTime 前最后一跳
                                          （须等下一 Tick 产生，沿用 V5 夹逼验证）
       computeDiffs → finalizeDiffs       决胜判定 + 拆账口径
       sortDiffs → buildGroups            diff 排序 + 分组派奖（链上）
       buildLeaves → buildSettlementRoot  结算叶 + SettlementRoot
       publish(rid)                       CCIP 双消息发 BSC（FTF + 全终局）
```

每个分步函数的 `n` 参数控制单笔交易的 Gas 消耗，Keeper 按链上实际 Gas 行情调批大小。

## 关键设计决策

1. **自包含双签名**：注单携带 `SessionAuth`（主钱包签：授权 sessionKey + 单注份数上限 + 有效期）
   和 `Bet`（sessionKey 签：roundId/guess/units/nonce），合约验双签。
   假 sessionKey 没有主钱包授权，伪造注单在源头被拒——这是封堵"Relay 伪造输入"的唯一机制。
2. **“0–5 分下注”= 时间窗**：每轮第 0–5 分钟接单，之后 `bet()` 按区块时间戳直接 revert。
   “超过 5 分拒绝接单”在链上强制执行，不依赖 Relay 校验。（已确认：指时间，不是注额上限。）
3. **统一票面制（沿用 V5.8）**：每注 = 1 张票，金额 = 当轮票价（`ticketForPool` 阶梯），
   注单不带金额。V5.8 全部奖金公式与不变量原封不动成立。
   Session Key 被盗的合约层防线改为 **SessionAuth.maxBets 授权注数上限**（合约计数强制），
   对敲盗刷损失被压到 maxBets × 票价 以内。
4. **结算叶覆盖全部注单**：叶 = `(rid, player, nonce, payout)`，输家 payout=0，stake=当轮 ticket。
   BSC 侧凭 Merkle proof 逐笔记账：扣 ticket、入 payout，资金完全闭合，无需信任任何链下账本。
5. **账务公式即协议**：pool/rake/cycle 全部沿用 V5.8 整数公式（含除法舍入方向）。
   BSC GuessV6 必须逐字复刻，否则守恒校验必然失败——这是镜像纪律，改一边必须改另一边。
6. **CCIP 双消息**：同一载荷发两条——FTF 快消息（`fastExtraArgs`，秒级~2 分钟，供快速记账）
   与全终局慢消息（`finalExtraArgs`，提现终审）。两条消息的费用以原生币从合约余额支付。
7. **Operator 角色消失**：V5.8 的 `onlyOperator` 申报/提交全部删除， replaced by permissionless
   分步计算。Owner 仅剩参数管理（周期/奖池参数/CCIP 配置），无资金权限。

## 与 V5.8 的规则对应

| V5.8 | V6 MegaETH |
|---|---|
| Operator 提交 BetRoot | 逐单上链 + 链上构建 BetRoot |
| Operator 申报 bestDiff/counts + proveFraud 挑战 | 链上 computeDiffs 直接算出，无申报无挑战 |
| SettlementRoot SMT 申报 + 锚点校验 | 链上 buildGroups/buildLeaves 直接计算派奖 |
| PHP 按台账入账/退款 | BSC GuessAccount 凭结算叶 proof 记账；流局消息触发退款 |
| 挑战窗口 | 取消（无需挑战，链上计算即终局）；终审职责移交 CCIP 全终局消息 |

## 部署参数（待定值）

| 参数 | 说明 |
|---|---|
| `genesisSlot` | 10 分钟格点起点（unix 秒，600 对齐） |
| `feed` | MegaETH 上 Chainlink BTC/USD feed 地址（需查实，0.5% 偏差触发） |
| `vrfCoordinator` | MegaETH 上 VRF Coordinator；**若 MegaETH 无 VRF，传 address(0)**，随机决胜路径自动关闭（仅保留自然/强制决胜） |
| `ccipRouter` / `bscChainSelector` | CCIP 主网目录查 MegaETH→BSC lane；**lane 是否存在需先确认** |
| `bscReceiver` | BSC GuessV6 合约地址（待开发） |
| `fastExtraArgs` / `finalExtraArgs` | 按 CCIP 2.0 文档配置；FTF 初期建议确认深度 10–20 区块，跑稳后下调 |

## 遗留项

- [x] ~~"分"的语义确认~~ 已确认：0–5 分 = 下注时间窗，统一票面制
- [ ] MegaETH Chainlink VRF 可用性确认；不可用时评估替代随机源
- [ ] `ticketForPool` 升档公式与 V5.8 原实现核对（原函数在被截断的代码段中，此处按注释复刻）
- [ ] CCIP MegaETH→BSC lane 与 FTF 支持情况；`extraArgs` 具体编码按部署时 CCIP 版本文档
- [ ] BSC 侧：GuessV6 接收端（幂等 + 镜像复算 + sender 白名单）、GuessAccount 记账、WITHDRAW、SessionManager
- [ ] Keeper 服务：监听事件驱动各阶段调用，批大小自适应
- [ ] 审计：两份合约上线前全部过专业审计
