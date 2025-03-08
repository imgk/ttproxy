package cmd

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/imgk/ttproxy"
)

func Main() {

	cfg := ttproxy.Config{}

	flag.StringVar(&cfg.HostPort, "server", "test.cc", "proxy server address: host:port")
	flag.StringVar(&cfg.TProxyAddr, "tproxy", "127.0.0.1:7789", "tproxy listen address: host:port")
	flag.StringVar(&cfg.Auth.User, "user", "test", "proxy server user name")
	flag.StringVar(&cfg.Auth.Password, "password", "test1234", "proxy server password")
	flag.DurationVar(&cfg.Timeout, "timeout", time.Minute*3, "timeout duration for UDP connection")
	flag.BoolVar(&cfg.EnableTLS, "tls", false, "use tls to connect proxy server")
	flag.BoolVar(&cfg.PProf, "pprof", false, "enable net/http/pprof")
	flag.StringVar(&cfg.HTTPAddr, "httpproxy", "", "enable http proxy")
	flag.Parse()

	slog.Info("start ttproxy: a transparent proxy client")
	if err := (&ttproxy.Server{}).Serve(cfg); err != nil {
		slog.Error(fmt.Sprintf("start tproxy error: %v", err))
		return
	}

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	<-sigint

	slog.Info("close ttproxy: a transparent proxy client")
}
