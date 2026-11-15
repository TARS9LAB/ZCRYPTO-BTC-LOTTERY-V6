package main

import (
        "context"
        "encoding/json"
        "log"
        "net/http"
        "time"
)

// BetRequest 为 PHP 扇出到每个 relay 的注单请求体。
// user/sessionKey/roundId/guess/nonce/sig 与 GuessV7.bet() 参数一一对应；
// sig 是 sessionKey 对 EIP-712 Bet(user, roundId, guess, nonce) 的签名。
type BetRequest struct {
        User       string `json:"user"`
        SessionKey string `json:"sessionKey"`
        RoundID    uint64 `json:"roundId"`
        Guess      uint64 `json:"guess"`
        Nonce      uint64 `json:"nonce"`
        Sig        string `json:"sig"`
}

type betResponse struct {
        Status string `json:"status"`
        TxHash string `json:"txHash,omitempty"`
        Reason string `json:"reason,omitempty"`
        Relay  string `json:"relay"`
}

type server struct {
        cfg *Config
        sub *Submitter
}

func (s *server) withAuth(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                if s.cfg.AuthToken != "" && r.Header.Get("X-Relay-Token") != s.cfg.AuthToken {
                        writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad token"})
                        return
                }
                next(w, r)
        }
}

// POST /v1/bet —— 接收一笔注单并尽力上链。
// 语义约定（PHP 聚合判断用）：
//
//      200 + status in {sent, confirmed, already_onchain, confirmed_by_peer} → 已受理
//      422 + status=rejected_precheck + reason                              → 合约预检拒绝（丢弃）
//      502 + status=send_failed                                             → 链/RPC 故障，可重试
//      400 / 401                                                            → 请求本身有问题
func (s *server) handleBet(w http.ResponseWriter, r *http.Request) {
        var req BetRequest
        if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
                return
        }
        if req.RoundID == 0 {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "roundId 必须 > 0"})
                return
        }
        ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
        defer cancel()
        status, txHash, reason := s.sub.Submit(ctx, req)
        resp := betResponse{Status: status, TxHash: txHash, Reason: reason, Relay: s.cfg.RelayID}
        switch status {
        case stSent, stConfirmed, stConfirmedByPeer, stAlreadyOnChain:
                writeJSON(w, http.StatusOK, resp)
        case stRejected:
                writeJSON(w, http.StatusUnprocessableEntity, resp)
        default: // send_failed / unknown
                writeJSON(w, http.StatusBadGateway, resp)
        }
}

// GET /v1/bet/status?user=0x..&nonce=123
// 链上 usedNonce 是最终事实；local 字段只是本 relay 的处理记录（可能为空）。
func (s *server) handleBetStatus(w http.ResponseWriter, r *http.Request) {
        q := r.URL.Query()
        user, err := parseHexAddress(q.Get("user"))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
                return
        }
        var nonce uint64
        if _, err := parseUint(q.Get("nonce"), &nonce); err != nil || q.Get("nonce") == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce 必须是非负整数"})
                return
        }
        ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
        defer cancel()
        onChain, err := s.sub.usedNonce(ctx, user, nonce)
        if err != nil {
                writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
                return
        }
        out := map[string]interface{}{"onChain": onChain, "relay": s.cfg.RelayID}
        key := recordKey(BetRequest{User: user.Hex(), Nonce: nonce})
        if v, ok := s.sub.records.Load(key); ok {
                status, txHash, reason, updatedAt := v.(*Record).snapshot()
                out["local"] = map[string]interface{}{
                        "status": status, "txHash": txHash, "reason": reason, "updatedAt": updatedAt,
                }
        }
        writeJSON(w, http.StatusOK, out)
}

// GET /healthz —— 探活 + 关键指标（余额、nonce、链头）。
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
        defer cancel()
        out := map[string]interface{}{"relay": s.cfg.RelayID, "from": s.sub.from.Hex()}
        head, err := s.sub.ec.HeaderByNumber(ctx, nil)
        if err != nil {
                out["ok"] = false
                out["error"] = err.Error()
                writeJSON(w, http.StatusBadGateway, out)
                return
        }
        bal, _ := s.sub.ec.BalanceAt(ctx, s.sub.from, nil)
        out["ok"] = true
        out["chainId"] = s.sub.chainID.String()
        out["head"] = head.Number.String()
        out["headTime"] = head.Time
        out["balanceWei"] = bal.String()
        writeJSON(w, http.StatusOK, out)
}

func (s *server) routes() *http.ServeMux {
        mux := http.NewServeMux()
        mux.HandleFunc("POST /v1/bet", s.withAuth(s.handleBet))
        mux.HandleFunc("GET /v1/bet/status", s.withAuth(s.handleBetStatus))
        mux.HandleFunc("GET /healthz", s.handleHealth)
        return mux
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(code)
        if err := json.NewEncoder(w).Encode(v); err != nil {
                log.Printf("写响应失败: %v", err)
        }
}

// parseUint 解析十进制字符串到 uint64（避免引入额外依赖）。
func parseUint(s string, out *uint64) (bool, error) {
        var n uint64
        if s == "" {
                return false, errEmpty
        }
        for _, c := range s {
                if c < '0' || c > '9' {
                        return false, errBadNum
                }
                n = n*10 + uint64(c-'0')
        }
        *out = n
        return true, nil
}
