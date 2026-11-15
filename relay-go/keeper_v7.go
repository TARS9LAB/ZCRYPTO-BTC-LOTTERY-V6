package main

// ZCrypto V7 链上状态推进器（仅 MegaETH 测试网 6343）。
// 共享现有 RELAY Submitter 的发送钱包、Nonce 锁与 WAL；同一个 Go 进程中独立 goroutine。
// 默认只读；设置 RELAY_KEEPER_ENABLED=1 才允许开局及结算交易。
// 所有决定都以链上状态为准，不依赖 Redis/MySQL 或其它 RELAY。

import (
        "context"
        "errors"
        "fmt"
        "log"
        "math/big"
        "os"
        "strconv"
        "strings"
        "time"

        "github.com/ethereum/go-ethereum"
        "github.com/ethereum/go-ethereum/common"
)

const keeperTestChainID = 6343

type KeeperV7 struct {
        sub          *Submitter
        settle       common.Address
        feed         common.Address
        enabled      bool
        maxBets      uint64
        maxGroups    uint64
        maxSortSteps uint64
        delay        time.Duration
        // 本机一次只允许一笔状态迁移在等待确认，防止旧状态导致连续重复广播。
        pendingHash   common.Hash
        pendingAction string
        pendingAt     time.Time
        lastDryRun    string
        lastDryRunAt  time.Time
}

func NewKeeperV7(ctx context.Context, sub *Submitter) (*KeeperV7, error) {
        if sub.chainID.Cmp(big.NewInt(keeperTestChainID)) != 0 || sub.cfg.ChainID != keeperTestChainID {
                return nil, fmt.Errorf("Keeper 只允许 MegaETH TESTNET chainId=%d", keeperTestChainID)
        }
        v := strings.TrimSpace(os.Getenv("RELAY_SETTLE_CONTRACT"))
        if !common.IsHexAddress(v) {
                return nil, errors.New("需要配置 RELAY_SETTLE_CONTRACT（GuessSettleV7 测试网地址）")
        }
        k := &KeeperV7{sub: sub, settle: common.HexToAddress(v), enabled: os.Getenv("RELAY_KEEPER_ENABLED") == "1", delay: 2 * time.Second, maxBets: 50, maxGroups: 50, maxSortSteps: 50}
        for _, x := range []struct {
                env string
                ptr *uint64
        }{{"RELAY_KEEPER_MAX_BETS", &k.maxBets}, {"RELAY_KEEPER_MAX_GROUPS", &k.maxGroups}, {"RELAY_KEEPER_SORT_STEPS", &k.maxSortSteps}} {
                if s := os.Getenv(x.env); s != "" {
                        n, e := strconv.ParseUint(s, 10, 64)
                        if e != nil || n < 1 || n > 500 {
                                return nil, fmt.Errorf("%s 必须在 1..500", x.env)
                        }
                        *x.ptr = n
                }
        }
        // 检查实际 RPC、代码和双向绑定，防止错误地址烧 Gas。
        chain, err := sub.ec.ChainID(ctx)
        if err != nil || chain.Cmp(big.NewInt(keeperTestChainID)) != 0 {
                return nil, errors.New("RPC 非 MegaETH 测试网")
        }
        code, err := sub.ec.CodeAt(ctx, k.settle, nil)
        if err != nil || len(code) == 0 {
                return nil, errors.New("Settle 地址无合约代码")
        }
        addr, err := k.readAddress(ctx, sub.contract, "settleContract()")
        if err != nil || addr != k.settle {
                return nil, errors.New("GuessV7.settleContract 绑定不匹配")
        }
        addr, err = k.readAddress(ctx, k.settle, "betContract()")
        if err != nil || addr != sub.contract {
                return nil, errors.New("GuessSettleV7.betContract 绑定不匹配")
        }
        addr, err = k.readAddress(ctx, k.settle, "feed()")
        if err != nil || addr == (common.Address{}) {
                return nil, errors.New("无法读取 Chainlink Feed")
        }
        k.feed = addr
        log.Printf("[%s/keeper] ready TESTNET=6343 settle=%s feed=%s writeEnabled=%v", sub.cfg.RelayID, k.settle.Hex(), k.feed.Hex(), k.enabled)
        return k, nil
}

func (k *KeeperV7) read(ctx context.Context, to common.Address, sig string, args ...uint64) ([]byte, error) {
        data := append([]byte{}, selectorOf(sig)...)
        for _, v := range args {
                data = append(data, wordU64(v)...)
        }
        return k.sub.ec.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
}
func keeperWord(b []byte, i int) (*big.Int, error) {
        if len(b) < (i+1)*32 {
                return nil, fmt.Errorf("ABI 输出过短: got %d need %d", len(b), (i+1)*32)
        }
        return new(big.Int).SetBytes(b[i*32 : (i+1)*32]), nil
}
func (k *KeeperV7) readUint(ctx context.Context, to common.Address, sig string, args ...uint64) (uint64, error) {
        b, e := k.read(ctx, to, sig, args...)
        if e != nil {
                return 0, e
        }
        w, e := keeperWord(b, 0)
        if e != nil {
                return 0, e
        }
        if !w.IsUint64() {
                return 0, fmt.Errorf("%s 超过 uint64", sig)
        }
        return w.Uint64(), nil
}
func (k *KeeperV7) readAddress(ctx context.Context, to common.Address, sig string) (common.Address, error) {
        b, e := k.read(ctx, to, sig)
        if e != nil {
                return common.Address{}, e
        }
        if len(b) < 32 {
                return common.Address{}, errors.New("address ABI length")
        }
        return common.BytesToAddress(b[12:32]), nil
}

type keeperRound struct {
        State      uint8
        PriceTime  uint64
        BetCount   uint64
        DiffCursor uint64
        VRFReady   bool
        VRFRequest *big.Int
        GroupCount uint64
}

func (k *KeeperV7) round(ctx context.Context, rid uint64) (keeperRound, error) {
        b, e := k.read(ctx, k.settle, "srounds(uint256)", rid)
        if e != nil {
                return keeperRound{}, e
        }
        if len(b) < 36*32 {
                return keeperRound{}, fmt.Errorf("srounds 返回 %d bytes，不符合预期36字段，禁止自动结算", len(b))
        }
        x := func(i int) uint64 { v, _ := keeperWord(b, i); return v.Uint64() }
        req, _ := keeperWord(b, 23)
        return keeperRound{State: uint8(x(0)), PriceTime: x(1), BetCount: x(6), DiffCursor: x(24), VRFReady: x(21) != 0, VRFRequest: req, GroupCount: x(16)}, nil
}

func keeperCalldata(sig string, nums ...uint64) []byte {
        b := append([]byte{}, selectorOf(sig)...)
        for _, n := range nums {
                b = append(b, wordU64(n)...)
        }
        return b
}

// 合约多阶段交易之前使用 eth_call 模拟；模拟失败时不广播。
func (k *KeeperV7) submit(ctx context.Context, to common.Address, name string, data []byte) error {
    ////
    // 测试模式：只允许 startRound
    if k.enabled &&
        os.Getenv("RELAY_KEEPER_START_ONLY") == "1" &&
        !strings.HasPrefix(name, "startRound(") {
        return nil
    }
    
    // 测试模式：只允许 closeRound
    if k.enabled &&
        os.Getenv("RELAY_KEEPER_CLOSE_ONLY") == "1" &&
        !strings.HasPrefix(name, "closeRound(") {
        return nil
    }
    //////
        _, err := k.sub.ec.CallContract(ctx, ethereum.CallMsg{From: k.sub.from, To: &to, Data: data}, nil)
        if err != nil {
                return fmt.Errorf("%s 预检拒绝: %w", name, err)
        }
        if !k.enabled {
                if k.lastDryRun != name || time.Since(k.lastDryRunAt) > 30*time.Second {
                        log.Printf("[%s/keeper] DRY-RUN %s", k.sub.cfg.RelayID, name)
                        k.lastDryRun = name
                        k.lastDryRunAt = time.Now()
                }
                return nil
        }
        tx, e := k.sub.buildAndSendTo(ctx, to, data)
        if tx != nil {
                k.pendingHash = tx.Hash()
                k.pendingAction = name
                k.pendingAt = time.Now()
                log.Printf("[%s/keeper] submitted %s tx=%s err=%v", k.sub.cfg.RelayID, name, tx.Hash(), e)
        }
        if e != nil {
                return e
        }
        return nil
}

func (k *KeeperV7) pending(ctx context.Context) (bool, error) {
        if k.pendingHash == (common.Hash{}) {
                return false, nil
        }
        receipt, e := k.sub.ec.TransactionReceipt(ctx, k.pendingHash)
        if e == nil && receipt != nil {
                log.Printf("[%s/keeper] receipt %s status=%d tx=%s", k.sub.cfg.RelayID, k.pendingAction, receipt.Status, k.pendingHash)
                k.pendingHash = common.Hash{}
                k.pendingAction = ""
                return false, nil
        }
        // tx 未确认时不持续发送相同操作；不因为 timeout 随意重用发送方 Nonce。
        if time.Since(k.pendingAt) > 90*time.Second {
                log.Printf("[%s/keeper] 等待交易确认 %s tx=%s，禁止盲目再发", k.sub.cfg.RelayID, k.pendingAction, k.pendingHash)
        }
        return true, nil
}

// Chainlink priceTime 要求 A.updatedAt <= priceTime < B.updatedAt。
// 只在当前 phase 内二分；旧 phase / 缺失的下一跳一律等待，不猜测价格。
func (k *KeeperV7) oracleRound(ctx context.Context, target uint64) (*big.Int, error) {
        latest, e := k.read(ctx, k.feed, "latestRoundData()")
        if e != nil {
                return nil, e
        }
        lid, e := keeperWord(latest, 0)
        if e != nil {
                return nil, e
        }
        phase := new(big.Int).Rsh(new(big.Int).Set(lid), 64)
        hi := new(big.Int).And(lid, new(big.Int).SetUint64(^uint64(0))).Uint64()
        if hi == 0 {
                return nil, errors.New("Chainlink 当前 phase 没有可查 round")
        }
        idFor := func(n uint64) *big.Int {
                return new(big.Int).Or(new(big.Int).Lsh(new(big.Int).Set(phase), 64), new(big.Int).SetUint64(n))
        }
        getStamp := func(id *big.Int) (uint64, error) {
                d := append(append([]byte{}, selectorOf("getRoundData(uint80)")...), pad32(id.Bytes())...)
                b, err := k.sub.ec.CallContract(ctx, ethereum.CallMsg{To: &k.feed, Data: d}, nil)
                if err != nil {
                        return 0, err
                }
                round, err := keeperWord(b, 0)
                if err != nil {
                        return 0, err
                }
                if round.Cmp(id) != 0 {
                        return 0, errors.New("Chainlink roundId 不匹配")
                }
                stamp, err := keeperWord(b, 3)
                if err != nil {
                        return 0, err
                }
                if !stamp.IsUint64() || stamp.Sign() == 0 {
                        return 0, errors.New("Chainlink updatedAt 无效")
                }
                return stamp.Uint64(), nil
        }
        lo, found := uint64(1), uint64(0)
        for lo <= hi {
                mid := lo + (hi-lo)/2
                stamp, err := getStamp(idFor(mid))
                if err != nil {
                        return nil, err
                }
                if stamp <= target {
                        found = mid
                        lo = mid + 1
                } else {
                        if mid == 0 {
                                break
                        }
                        hi = mid - 1
                }
        }
        if found == 0 {
                return nil, errors.New("Oracle target 不在当前 phase；不能自动选择过期/其他 phase 价格")
        }
        candidate := idFor(found)
        next := new(big.Int).Add(candidate, big.NewInt(1))
        stamp, e := getStamp(next)
        if e != nil {
                return nil, fmt.Errorf("等待 TickB: %w", e)
        }
        if stamp <= target {
                return nil, errors.New("等待 priceTime 后的 TickB")
        }
        return candidate, nil
}

// Run 由 main goroutine 启动。单台一次仅提交一个状态转换，收到回执后重读状态。
func (k *KeeperV7) Run(ctx context.Context) {
        tick := time.NewTicker(k.delay)
        defer tick.Stop()
        for {
                select {
                case <-ctx.Done():
                        return
                case <-tick.C:
                        c, cancel := context.WithTimeout(ctx, 12*time.Second)
                        err := k.Tick(c)
                        cancel()
                        if err != nil {
                                log.Printf("[%s/keeper] tick: %v", k.sub.cfg.RelayID, err)
                        }
                }
        }
}

func (k *KeeperV7) Tick(ctx context.Context) error {
        if waiting, e := k.pending(ctx); e != nil {
                return e
        } else if waiting {
                return nil
        }
        head, e := k.sub.ec.HeaderByNumber(ctx, nil)
        if e != nil {
                return e
        }
        now := head.Time
        genesis, e := k.readUint(ctx, k.sub.contract, "genesisSlot()")
        if e != nil {
                return e
        }
        if now < genesis {
                return nil
        }
        current := (now-genesis)/600 + 1
        last, e := k.readUint(ctx, k.sub.contract, "lastStartedRid()")
        if e != nil {
                return e
        }
        // 优先处理上一轮；等链上达到经济终态后再尝试开局。
        if last > 0 {
                r, e := k.sub.rounds(ctx, new(big.Int).SetUint64(last))
                if e != nil {
                        return e
                }
                s, e := k.round(ctx, last)
                if e != nil {
                        return e
                }
                if r.State == 1 && now >= r.BettingClose {
                        return k.submit(ctx, k.sub.contract, fmt.Sprintf("closeRound(%d)", last), keeperCalldata("closeRound(uint256)", last))
                }
                if r.State == 2 {
                        if e := k.advanceSettlement(ctx, last, now, s); e != nil {
                                return e
                        }
                        // 非终态不尝试下一轮开局；推进结果需要等回执重读。
                        if k.pendingHash != (common.Hash{}) || s.State != 7 && s.State != 8 && s.State != 11 && s.State != 12 {
                                return nil
                        }
                }
        }
        if now >= genesis+(current-1)*600+120 {
                return nil
        }
        r, e := k.sub.rounds(ctx, new(big.Int).SetUint64(current))
        if e != nil {
                return e
        }
        if r.BettingClose != 0 {
                return nil
        }
        if last > 0 {
                finalData, e := k.read(ctx, k.settle, "isRoundFinal(uint256)", last)
                if e != nil {
                        return e
                }
                fin, e := decodeBool(finalData)
                if e != nil {
                        return e
                }
                if !fin {
                        return nil
                }
        }
        return k.submit(ctx, k.sub.contract, fmt.Sprintf("startRound(%d)", current), keeperCalldata("startRound(uint256)", current))
}
func (k *KeeperV7) advanceSettlement(ctx context.Context, rid, now uint64, s keeperRound) error {
        name := ""
        to := k.settle
        var data []byte
        switch s.State {
        case 0:
                name = "beginRound"
                data = keeperCalldata("beginRound(uint256)", rid)
        case 1:
                if now < s.PriceTime {
                        return nil
                }
                oracleID, e := k.oracleRound(ctx, s.PriceTime)
                if e != nil {
                        return e
                }
                name = "anchorPrice"
                data = append(keeperCalldata("anchorPrice(uint256,uint80)", rid), pad32(oracleID.Bytes())...)
        case 2:
                // 若当前 VRF 已启用且达门槛，但未请求/返回，需要在 computeDiffs 前处理。
                vrfEnabled, e := k.read(ctx, to, "currentVrfEnabled()")
                if e != nil {
                        return e
                }
                enabled, e := decodeBool(vrfEnabled)
                if e != nil {
                        return e
                }
                pool, e := k.read(ctx, to, "pool()")
                if e != nil {
                        return e
                }
                min, e := k.read(ctx, to, "currentMinVrfJackpot()")
                if e != nil {
                        return e
                }
                count, e := k.readUint(ctx, to, "cycleRoundCount()")
                if e != nil {
                        return e
                }
                max, e := k.readUint(ctx, to, "cycleMaxRounds()")
                if e != nil {
                        return e
                }
                p, _ := keeperWord(pool, 0)
                m, _ := keeperWord(min, 0)
                eligible := enabled && p.Cmp(m) >= 0 && count+1 < max
                if eligible && s.VRFRequest.Sign() == 0 {
                        name = "requestVrf"
                        data = keeperCalldata("requestVrf(uint256)", rid)
                } else if eligible && !s.VRFReady {
                        return nil
                } else {
                        name = "computeDiffs"
                        data = keeperCalldata("computeDiffs(uint256,uint256)", rid, k.maxBets)
                }
        case 3:
                name = "sortDiffs"
                data = keeperCalldata("sortDiffs(uint256,uint256)", rid, k.maxSortSteps)
        case 4, 5:
                name = "buildGroups"
                data = keeperCalldata("buildGroups(uint256,uint256)", rid, k.maxGroups)
        case 6:
                name = "finalizeAccounting"
                data = keeperCalldata("finalizeAccounting(uint256,uint256)", rid, k.maxGroups)
        case 7:
                name = "payWinners"
                data = keeperCalldata("payWinners(uint256,uint256)", rid, k.maxBets)
        case 8, 11, 12:
                return nil
        case 10:
                name = "voidApply"
                data = keeperCalldata("voidApply(uint256,uint256)", rid, k.maxBets)
        default:
                // 流局属于资金敏感异常路径，单独开启，不能仅因时间到就自动退款。
                log.Printf("[%s/keeper] round=%d state=%d requires manual review (voidInit disabled)", k.sub.cfg.RelayID, rid, s.State)
                return nil
        }
        return k.submit(ctx, to, fmt.Sprintf("%s(%d)", name, rid), data)
}
