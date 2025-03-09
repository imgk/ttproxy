# ttproxy -- The Linux TProxy Client

A simple command line tool which supports HTTP CONNECT method and UDP in HTTP [RFC9298](https://datatracker.ietf.org/doc/html/rfc9298).

```
Usage of ttproxy:
  -httpproxy string
    	enable http proxy host:port
  -password string
    	proxy server password (default "test1234")
  -pprof
    	enable net/http/pprof
  -server string
    	proxy server address: host:port (default "test.cc:443") or chained "socks5://192.168.1.1:1080;test.cc:443"
  -timeout duration
    	timeout duration for UDP connection (default 3m0s)
  -tls
    	use tls to connect proxy server
  -tproxy string
    	tproxy listen address: host:port (default "127.0.0.1:7789")
  -user string
    	proxy server user name (default "test")
```

## Server
The suggested server is caddy with module customzied [forwardproxy](https://github.com/imgk/forwardproxy).
