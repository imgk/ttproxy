package cmd

import (
	"flag"
	"log/slog"
	"time"

	"github.com/imgk/ttproxy"
)

func Main() {

	cfg := ttproxy.Config{}

	flag.StringVar(&cfg.HostPort, "server", "test.cc", "proxy server address: host:port")
	flag.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:7789", "tproxy listen address: host:port")
	flag.StringVar(&cfg.Auth.User, "user", "test", "proxy server user name")
	flag.StringVar(&cfg.Auth.Password, "password", "test1234", "proxy server password")
	flag.DurationVar(&cfg.Timeout, "timeout", time.Minute*3, "UDP timeout")
	flag.Parse()

	slog.Info("start ttproxy: a transparent proxy client")
	(&ttproxy.Server{}).Serve(cfg)
	slog.Info("close ttproxy: a transparent proxy client")
}
