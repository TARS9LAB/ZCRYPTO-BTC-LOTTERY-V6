package main

import (
        "encoding/json"
        "fmt"
        "os"
        "strings"
)

// Config 为单个 relay 实例的全部配置。
// 三个 relay 实例除 listen / privateKey / relayId 外其余保持一致。
type Config struct {
        // RelayID 仅用于日志与响应标识（如 "relay-1"）。
        RelayID string `json:"relayId"`
        // Listen HTTP 监听地址。生产上绑内网地址，前面由 PHP 扇出调用。
        Listen string `json:"listen"`
        // AuthToken 调用方鉴权：请求头 X-Relay-Token 必须一致；留空表示不鉴权（仅限内网调试）。
        AuthToken string `json:"authToken"`
        // RPCURL MegaETH RPC。测试网 https://carrot.megaeth.com/rpc
        RPCURL string `json:"rpcUrl"`
        // ChainID 期望链 ID；0 = 启动时从节点读取。测试网 6343，主网 4326。
        ChainID int64 `json:"chainId"`
        // Contract GuessV7 合约地址。
        Contract string `json:"contract"`
        // PrivateKey relay 出 Gas 的钱包私钥（十六进制，可带 0x）。
        // 该 key 只付 Gas、对注单容无任何权限；三个 relay 必须用三把不同的 key。
        // 建议留空、走环境变量 RELAY_PRIVATE_KEY 注入。
        PrivateKey string `json:"privateKey"`
        // GasBufferPct 估算 gas 的上浮百分比。默认 20。
        // 项目实测教训：嵌套合约调用 estimateGas 可能低估（1/64 规则），必须显式上浮。
        GasBufferPct int64 `json:"gasBufferPct"`
        // GasPriceMultiplierPct SuggestGasPrice 上浮百分比，默认 110。
        GasPriceMultiplierPct int64 `json:"gasPriceMultiplierPct"`
        // MaxGasPriceGwei gasPrice 保护上限（gwei），0 = 不限制。
        MaxGasPriceGwei float64 `json:"maxGasPriceGwei"`
        // CloseMarginSec 关窗提前量（秒）：距 bettingClose 不足该秒数直接拒单，
        // 避免交易在路上时窗口已关。默认 3。
        CloseMarginSec int64 `json:"closeMarginSec"`
        // ConfirmTimeoutSec 回执跟踪超时（秒），默认 90。超时后状态置 unknown，
        // 真伪以链上 usedNonce 为准。
        ConfirmTimeoutSec int64 `json:"confirmTimeoutSec"`
}

func loadConfig(path string) (*Config, error) {
        raw, err := os.ReadFile(path)
        if err != nil {
                return nil, fmt.Errorf("read config: %w", err)
        }
        cfg := &Config{
                RelayID:               "relay",
                Listen:                "127.0.0.1:8081",
                GasBufferPct:          20,
                GasPriceMultiplierPct: 110,
                CloseMarginSec:        3,
                ConfirmTimeoutSec:     90,
        }
        if err := json.Unmarshal(raw, cfg); err != nil {
                return nil, fmt.Errorf("parse config: %w", err)
        }
        // 环境变量优先于文件，避免私钥落盘。
        if v := strings.TrimSpace(os.Getenv("RELAY_PRIVATE_KEY")); v != "" {
                cfg.PrivateKey = v
        }
        if v := strings.TrimSpace(os.Getenv("RELAY_RPC_URL")); v != "" {
                cfg.RPCURL = v
        }
        if cfg.RPCURL == "" {
                return nil, fmt.Errorf("rpcUrl is required")
        }
        if cfg.Contract == "" {
                return nil, fmt.Errorf("contract is required")
        }
        if cfg.PrivateKey == "" {
                return nil, fmt.Errorf("privateKey is required (or set RELAY_PRIVATE_KEY)")
        }
        return cfg, nil
}
