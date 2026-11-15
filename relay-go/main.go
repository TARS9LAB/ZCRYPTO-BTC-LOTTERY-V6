package main

import (
        "context"
        "errors"
        "flag"
        "log"
        "net/http"
        "os"
        "os/signal"
        "syscall"
        "time"
)

var (
        errEmpty  = errors.New("empty")
        errBadNum = errors.New("bad number")
)

func main() {
        cfgPath := flag.String("config", "config.json", "配置文件路径")
        flag.Parse()

        cfg, err := loadConfig(*cfgPath)
        if err != nil {
                log.Fatalf("配置错误: %v", err)
        }

        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        sub, err := NewSubmitter(ctx, cfg)
        cancel()
        if err != nil {
                log.Fatalf("启动失败: %v", err)
        }

        // Optional embedded Keeper; defaults to OFF, and always checks MegaETH testnet chain ID 6343.
        keeperCtx, stopKeeper := context.WithCancel(context.Background())
        if os.Getenv("RELAY_KEEPER_START") == "1" {
                checkCtx, stopCheck := context.WithTimeout(context.Background(), 15*time.Second)
                keeper, keeperErr := NewKeeperV7(checkCtx, sub)
                stopCheck()
                if keeperErr != nil {
                        log.Fatalf("Keeper 启动检查失: %v", keeperErr)
                }
                go keeper.Run(keeperCtx)
        }
        defer stopKeeper()

        srv := &server{cfg: cfg, sub: sub}
        httpSrv := &http.Server{
                Addr:              cfg.Listen,
                Handler:           srv.routes(),
                ReadHeaderTimeout: 5 * time.Second,
        }

        go func() {
                log.Printf("[%s] 监听 %s", cfg.RelayID, cfg.Listen)
                if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
                        log.Fatalf("HTTP 服务异常: %v", err)
                }
        }()

        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
        <-sig
        log.Printf("[%s] 收到退出信号，优雅停机", cfg.RelayID)
        shutdownCtx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel2()
        stopKeeper()
        _ = httpSrv.Shutdown(shutdownCtx)
        _ = sub.Close()
}
