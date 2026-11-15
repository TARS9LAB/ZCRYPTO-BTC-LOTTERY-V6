package main

import (
        "bufio"
        "context"
        "crypto/ecdsa"
        "encoding/hex"
        "encoding/json"
        "errors"
        "fmt"
        "log"
        "math/big"
        "os"
        "path/filepath"
        "sort"
        "strconv"
        "strings"
        "sync"
        "syscall"
        "time"

        "github.com/ethereum/go-ethereum"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/core/types"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/ethereum/go-ethereum/ethclient"
)

// 依赖项目中已有的 Config、BetRequest、packBet、parseHexAddress、
// parseHexBytes、decodeRevert 等定义。替换旧 Submitter 文件，而不是新增同名定义。
//
// 对外 status 只表示此 RELAY 的处理进度，不代表下注链上成功。
const (
        stProcessing      = "processing"
        stSent            = "sent"
        stConfirmed       = "confirmed" // 保留兼容，最终状态由独立 Scanner 确定
        stConfirmedByPeer = "confirmed_by_peer"
        stAlreadyOnChain  = "already_onchain"
        stReverted        = "reverted"
        stRejected        = "rejected_precheck"
        stSendFailed      = "send_failed"
        stUnknown         = "unknown"
)

type Record struct {
        mu        sync.Mutex
        Req       BetRequest
        Status    string
        TxHash    string
        Reason    string
        UpdatedAt time.Time
}

func (r *Record) set(status, reason string) {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.Status, r.Reason, r.UpdatedAt = status, reason, time.Now()
}
func (r *Record) setTx(status, txHash, reason string) {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.Status, r.TxHash, r.Reason, r.UpdatedAt = status, txHash, reason, time.Now()
}
func (r *Record) snapshot() (status, txHash, reason string, updatedAt time.Time) {
        r.mu.Lock()
        defer r.mu.Unlock()
        return r.Status, r.TxHash, r.Reason, r.UpdatedAt
}

// WAL 中只保存外层签名交易（不保存私钥）。signed 先 fsync 后广播。
// 注意：WAL 是 append-only，需要由运维定期在确认已上链后进行归档/压缩。
type walEntry struct {
        Kind  string `json:"kind"` // signed 或 broadcast
        Nonce uint64 `json:"nonce"`
        Raw   string `json:"raw,omitempty"`
        Hash  string `json:"hash,omitempty"`
        Time  int64  `json:"time"`
}

type txJournal struct {
        mu   sync.Mutex
        file *os.File
        path string
}

func openJournal(path string) (*txJournal, error) {
        if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
                return nil, err
        }
        f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
        if err != nil {
                return nil, err
        }
        // 不允许两个 RELAY 进程共享同一 Nonce WAL / Gas 钱包。
        if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
                f.Close()
                return nil, fmt.Errorf("WAL 已被另一进程锁定: %w", err)
        }
        return &txJournal{file: f, path: path}, nil
}
func (j *txJournal) append(e walEntry) error {
        j.mu.Lock()
        defer j.mu.Unlock()
        b, err := json.Marshal(e)
        if err != nil {
                return err
        }
        b = append(b, '\n')
        if _, err = j.file.Write(b); err != nil {
                return err
        }
        return j.file.Sync()
}
func (j *txJournal) readSigned() (map[uint64]*types.Transaction, error) {
        j.mu.Lock()
        defer j.mu.Unlock()
        if _, err := j.file.Seek(0, 0); err != nil {
                return nil, err
        }
        defer j.file.Seek(0, 2)
        scanner := bufio.NewScanner(j.file)
        scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
        result := make(map[uint64]*types.Transaction)
        for scanner.Scan() {
                var item walEntry
                if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
                        return nil, fmt.Errorf("WAL 数据损坏：%w", err)
                }
                if item.Kind != "signed" {
                        continue
                }
                b, err := hex.DecodeString(item.Raw)
                if err != nil {
                        return nil, err
                }
                var tx types.Transaction
                if err := tx.UnmarshalBinary(b); err != nil {
                        return nil, err
                }
                if tx.Nonce() != item.Nonce {
                        return nil, errors.New("WAL nonce 不一致")
                }
                if old, exists := result[item.Nonce]; exists && old.Hash() != tx.Hash() {
                        return nil, fmt.Errorf("WAL 中 nonce=%d 有不同交易，必须人工恢复", item.Nonce)
                }
                result[item.Nonce] = &tx
        }
        if err := scanner.Err(); err != nil {
                return nil, err
        }
        return result, nil
}
func (j *txJournal) close() error {
        if j == nil || j.file == nil {
                return nil
        }
        return j.file.Close()
}

type cachedGas struct {
        price *big.Int
        until time.Time
}

type Submitter struct {
        cfg      *Config
        ec       *ethclient.Client
        key      *ecdsa.PrivateKey
        from     common.Address
        contract common.Address
        chainID  *big.Int

        // 持有直到 WAL 写入 + RPC 接受；宁可暂时减慢广播也不制造 Nonce 缺口。
        nonceMu     sync.Mutex
        nextNonce   uint64
        nonceSynced bool
        // 一旦 RPC 返回不确定结果，保留原交易，在其确定前不得分配后继 Nonce。
        unresolved *types.Transaction
        journal    *txJournal

        gasMu   sync.Mutex
        gas     cachedGas
        records sync.Map // user:nonce => *Record
}

func NewSubmitter(ctx context.Context, cfg *Config) (*Submitter, error) {
        ec, err := ethclient.DialContext(ctx, cfg.RPCURL)
        if err != nil {
                return nil, fmt.Errorf("连接 RPC: %w", err)
        }
        key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(cfg.PrivateKey), "0x"))
        if err != nil {
                ec.Close()
                return nil, err
        }
        chainID, err := ec.ChainID(ctx)
        if err != nil {
                ec.Close()
                return nil, err
        }
        if cfg.ChainID != 0 && chainID.Cmp(big.NewInt(cfg.ChainID)) != 0 {
                ec.Close()
                return nil, fmt.Errorf("chainId 不匹配: %s != %d", chainID, cfg.ChainID)
        }
        if !common.IsHexAddress(cfg.Contract) {
                ec.Close()
                return nil, errors.New("合约地址格式错误")
        }
        s := &Submitter{cfg: cfg, ec: ec, key: key, from: crypto.PubkeyToAddress(key.PublicKey), contract: common.HexToAddress(cfg.Contract), chainID: chainID}
        path := os.Getenv("RELAY_WAL_PATH")
        if path == "" {
                path = filepath.Join(".", "relay-"+cfg.RelayID+"-tx.wal")
        }
        j, err := openJournal(path)
        if err != nil {
                ec.Close()
                return nil, err
        }
        s.journal = j
        if err := s.recoverNonce(ctx); err != nil {
                j.close()
                ec.Close()
                return nil, fmt.Errorf("恢复 Nonce/WAL 失败: %w", err)
        }
        bal, err := ec.BalanceAt(ctx, s.from, nil)
        if err != nil {
                j.close()
                ec.Close()
                return nil, err
        }
        log.Printf("[%s] READY from=%s chain=%s contract=%s nextNonce=%d gasBalanceWei=%s WAL=%s", cfg.RelayID, s.from.Hex(), chainID, s.contract.Hex(), s.nextNonce, bal.String(), path)
        if bal.Sign() == 0 {
                log.Printf("[%s] 警告：RELAY Gas 钱包余额为零", cfg.RelayID)
        }
        return s, nil
}

// 恢复规则：以 latest 链上已打包的 Nonce 为基线，重播 WAL 中尚未打包的签名交易。
// PendingNonce 只用于防止与 WAL 之外的 Pending 交易冲突。该 RELAY 钱包必须独占。
func (s *Submitter) recoverNonce(ctx context.Context) error {
        s.nonceMu.Lock()
        defer s.nonceMu.Unlock()
        signed, err := s.journal.readSigned()
        if err != nil {
                return err
        }
        latest, err := s.ec.NonceAt(ctx, s.from, nil)
        if err != nil {
                return err
        }
        pending, err := s.ec.PendingNonceAt(ctx, s.from)
        if err != nil {
                return err
        }
        nonces := make([]uint64, 0, len(signed))
        for n := range signed {
                if n >= latest {
                        nonces = append(nonces, n)
                }
        }
        sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })
        if len(nonces) > 0 && nonces[0] > latest {
                return fmt.Errorf("WAL 缺失最早未确认 nonce=%d，找到的是 %d", latest, nonces[0])
        }
        expected := latest
        for _, n := range nonces {
                if n != expected {
                        return fmt.Errorf("WAL 存在 nonce 缺口: 缺 %d", expected)
                }
                expected++
                tx := signed[n]
                if err := s.ec.SendTransaction(ctx, tx); err != nil && !isAlreadyKnown(err) && !isNonceTooLow(err) {
                        return fmt.Errorf("恢复重播 nonce=%d tx=%s: %w", n, tx.Hash().Hex(), err)
                }
        }
        // 钱包被别的程序使用也会破坏连续性：拒绝盲目跳号。
        if pending > expected {
                return fmt.Errorf("RPC pendingNonce=%d 超过 WAL 链接末尾 %d：钱包可能被外部使用", pending, expected)
        }
        s.nextNonce = expected
        s.nonceSynced = true
        return nil
}

func isAlreadyKnown(err error) bool {
        if err == nil {
                return false
        }
        e := strings.ToLower(err.Error())
        return strings.Contains(e, "already known") || strings.Contains(e, "known transaction")
}
func isNonceTooLow(err error) bool {
        return err != nil && strings.Contains(strings.ToLower(err.Error()), "nonce too low")
}

// 只在发送互斥锁下运行。RPC 超时不意味着失败；先重播同一交易，不重新签名。
func (s *Submitter) resolveUncertain(ctx context.Context) error {
        if s.unresolved == nil {
                return nil
        }
        tx := s.unresolved
        err := s.ec.SendTransaction(ctx, tx)
        if err == nil || isAlreadyKnown(err) {
                s.unresolved = nil
                s.nextNonce = tx.Nonce() + 1
                return nil
        }
        if isNonceTooLow(err) {
                latest, e := s.ec.NonceAt(ctx, s.from, nil)
                if e == nil && latest > tx.Nonce() {
                        s.unresolved = nil
                        s.nextNonce = latest
                        return nil
                }
        }
        return fmt.Errorf("nonce=%d tx=%s 广播状态未知，暂停新交易: %w", tx.Nonce(), tx.Hash().Hex(), err)
}

// Gas Price 缓存：每 2 秒最多请求一次，避免每注调用 SuggestGasPrice。
func (s *Submitter) gasPrice(ctx context.Context) (*big.Int, error) {
        s.gasMu.Lock()
        defer s.gasMu.Unlock()
        if s.gas.price != nil && time.Now().Before(s.gas.until) {
                return new(big.Int).Set(s.gas.price), nil
        }
        p, err := s.ec.SuggestGasPrice(ctx)
        if err != nil {
                return nil, err
        }
        if s.cfg.GasPriceMultiplierPct <= 0 {
                return nil, errors.New("GasPriceMultiplierPct 必须 >0")
        }
        p.Mul(p, big.NewInt(s.cfg.GasPriceMultiplierPct))
        p.Div(p, big.NewInt(100))
        if p.Sign() <= 0 {
                return nil, errors.New("gas price 为零")
        }
        if s.cfg.MaxGasPriceGwei > 0 {
                // float64 只作为配置转换，不参与链上金额计算。
                capWei := new(big.Float).Mul(big.NewFloat(s.cfg.MaxGasPriceGwei), big.NewFloat(1e9))
                cap, _ := capWei.Int(nil)
                if p.Cmp(cap) > 0 {
                        return nil, fmt.Errorf("gasPrice %s 超过上限 %s", p, cap)
                }
        }
        s.gas = cachedGas{price: new(big.Int).Set(p), until: time.Now().Add(2 * time.Second)}
        return p, nil
}

// 可通过环境变量设置经压测确认的固定 Gas Limit；不设置时使用每注 EstimateGas。
func (s *Submitter) gasLimit(ctx context.Context, calldata []byte) (uint64, error) {
        if v := os.Getenv("RELAY_BET_GAS_LIMIT"); v != "" {
                limit, err := strconv.ParseUint(v, 10, 64)
                if err != nil || limit < 21000 {
                        return 0, errors.New("RELAY_BET_GAS_LIMIT 不合法")
                }
                return limit, nil
        }
        est, err := s.ec.EstimateGas(ctx, ethereum.CallMsg{From: s.from, To: &s.contract, Data: calldata})
        if err != nil {
                return 0, err
        }
        if s.cfg.GasBufferPct < 0 || s.cfg.GasBufferPct > 100 {
                return 0, errors.New("GasBufferPct 应在 0~100")
        }
        return est * uint64(100+s.cfg.GasBufferPct) / 100, nil
}

// Submit: 一次 eth_call 验证全量合约约束，再广播，不逐笔等待 Receipt。
func (s *Submitter) Submit(ctx context.Context, req BetRequest) (string, string, string) {
        user, err := parseHexAddress(req.User)
        if err != nil {
                return stRejected, "", err.Error()
        }
        sessionKey, err := parseHexAddress(req.SessionKey)
        if err != nil {
                return stRejected, "", err.Error()
        }
        sig, err := parseHexBytes(req.Sig)
        if err != nil || len(sig) != 65 {
                return stRejected, "", "betSig 必须为 65 字节"
        }
        // 用规范化地址，避免大小写别名绕过本地去重。
        key := strings.ToLower(user.Hex()) + ":" + strconv.FormatUint(req.Nonce, 10)
        rec := &Record{Req: req, Status: stProcessing, UpdatedAt: time.Now()}
        if actual, loaded := s.records.LoadOrStore(key, rec); loaded {
                status, hash, reason, _ := actual.(*Record).snapshot()
                return status, hash, reason
        }
        finish := func(status, hash, reason string) (string, string, string) {
                rec.setTx(status, hash, reason)
                // 预检失败可以释放本地 key；有效的下注不允许同一进程重复入队。
                if status == stRejected || status == stSendFailed {
                        s.records.CompareAndDelete(key, rec)
                }
                return status, hash, reason
        }
        calldata := packBet(user, sessionKey, new(big.Int).SetUint64(req.RoundID), req.Guess, req.Nonce, sig)
        // 容错：RPC 预检失败与合约拒绝需区分。此处拒绝提交（fail closed），避免恶意请求烧 Gas。
        if data, err := s.callContract(ctx, calldata, nil); err != nil {
                reason := decodeRevert(data)
                if len(data) == 0 {
                        return finish(stSendFailed, "", "eth_call/RPC 异常: "+err.Error())
                }
                return finish(stRejected, "", reason)
        }
        tx, err := s.buildAndSend(ctx, calldata)
        if tx == nil {
                return finish(stSendFailed, "", err.Error())
        }
        if err != nil {
                return finish(stUnknown, tx.Hash().Hex(), err.Error())
        }
        return finish(stSent, tx.Hash().Hex(), "")
}

// IMPORTANT: 串行化发送方 Nonce 分配和首次广播，以保证缺口不会被后续交易掩盖。
// 内存和磁盘 WAL 都是本机独立的，两个 RELAY 不共享钱包、Nonce 或文件。
func (s *Submitter) buildAndSend(ctx context.Context, calldata []byte) (*types.Transaction, error) {
        gasLimit, err := s.gasLimit(ctx, calldata)
        if err != nil {
                return nil, fmt.Errorf("GasLimit: %w", err)
        }
        return s.buildAndSendWithGas(ctx, s.contract, calldata, gasLimit)
}

// buildAndSendTo: 所有合约写交易共用同一钱包 Nonce、WAL 与发送互斥锁。
// Keeper 用此方法给 GuessV7 或 GuessSettleV7 发交易，绝不能另外管理相同钱包的 Nonce。
func (s *Submitter) buildAndSendTo(ctx context.Context, to common.Address, calldata []byte) (*types.Transaction, error) {
        gasLimit, err := s.estimateActionGas(ctx, to, calldata)
        if err != nil {
                return nil, fmt.Errorf("GasLimit: %w", err)
        }
        return s.buildAndSendWithGas(ctx, to, calldata, gasLimit)
}

func (s *Submitter) estimateActionGas(ctx context.Context, to common.Address, calldata []byte) (uint64, error) {
        est, err := s.ec.EstimateGas(ctx, ethereum.CallMsg{From: s.from, To: &to, Data: calldata})
        if err != nil {
                return 0, err
        }
        if s.cfg.GasBufferPct < 0 || s.cfg.GasBufferPct > 100 {
                return 0, errors.New("GasBufferPct 应在 0~100")
        }
        return est * uint64(100+s.cfg.GasBufferPct) / 100, nil
}

func (s *Submitter) buildAndSendWithGas(ctx context.Context, to common.Address, calldata []byte, gasLimit uint64) (*types.Transaction, error) {
        price, err := s.gasPrice(ctx)
        if err != nil {
                return nil, fmt.Errorf("GasPrice: %w", err)
        }
        s.nonceMu.Lock()
        defer s.nonceMu.Unlock()
        if err := s.resolveUncertain(ctx); err != nil {
                return nil, err
        }
        if !s.nonceSynced {
                return nil, errors.New("Nonce 未初始化")
        }
        nonce := s.nextNonce
        tx := types.NewTx(&types.LegacyTx{Nonce: nonce, To: &to, Value: big.NewInt(0), Gas: gasLimit, GasPrice: price, Data: calldata})
        signed, err := types.SignTx(tx, types.NewEIP155Signer(s.chainID), s.key)
        if err != nil {
                return nil, err
        }
        raw, err := signed.MarshalBinary()
        if err != nil {
                return nil, err
        }
        // WAL 必须先于 RPC 发送持久化；失败不允许消耗 Nonce。
        if err := s.journal.append(walEntry{Kind: "signed", Nonce: nonce, Raw: hex.EncodeToString(raw), Hash: signed.Hash().Hex(), Time: time.Now().Unix()}); err != nil {
                return nil, fmt.Errorf("持久化签名交易失败: %w", err)
        }
        s.unresolved = signed
        err = s.ec.SendTransaction(ctx, signed)
        if err != nil && !isAlreadyKnown(err) {
                // 不能把 replacement underpriced 或 RPC timeout 视作成功。
                // 后续 Submit 将先尝试重新广播原始签名交易。
                return signed, fmt.Errorf("广播状态未确定 nonce=%d tx=%s: %w", nonce, signed.Hash().Hex(), err)
        }
        s.unresolved = nil
        s.nextNonce++
        if err := s.journal.append(walEntry{Kind: "broadcast", Nonce: nonce, Hash: signed.Hash().Hex(), Time: time.Now().Unix()}); err != nil {
                log.Printf("[%s] WAL broadcast 标记失败，signed 已持久化: %v", s.cfg.RelayID, err)
        }
        return signed, nil
}

func (s *Submitter) callContract(ctx context.Context, calldata []byte, block *big.Int) ([]byte, error) {
        out, err := s.ec.CallContract(ctx, ethereum.CallMsg{From: s.from, To: &s.contract, Data: calldata}, block)
        if err != nil {
                return extractRevertData(err), err
        }
        return out, nil
}
func (s *Submitter) usedNonce(ctx context.Context, user common.Address, nonce uint64) (bool, error) {
        out, err := s.callContract(ctx, packUsedNonce(user, nonce), nil)
        if err != nil {
                return false, err
        }
        return decodeBool(out)
}
func (s *Submitter) rounds(ctx context.Context, roundID *big.Int) (*roundInfo, error) {
        out, err := s.callContract(ctx, packRounds(roundID), nil)
        if err != nil {
                return nil, err
        }
        return decodeRounds(out)
}
func extractRevertData(err error) []byte {
        type dataError interface{ ErrorData() interface{} }
        var de dataError
        if errors.As(err, &de) {
                if v, ok := de.ErrorData().(string); ok {
                        b, _ := hex.DecodeString(strings.TrimPrefix(v, "0x"))
                        return b
                }
        }
        return nil
}
func recordKey(req BetRequest) string {
        return strings.ToLower(req.User) + ":" + strconv.FormatUint(req.Nonce, 10)
}

// 进程退出时显式调用。不要在外部关闭 WAL 后继续 Submit。
func (s *Submitter) Close() error {
        s.nonceMu.Lock()
        defer s.nonceMu.Unlock()
        var err error
        if s.journal != nil {
                err = s.journal.close()
        }
        if s.ec != nil {
                s.ec.Close()
        }
        return err
}
