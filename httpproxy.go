package ttproxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// slog.Error("http method error: %v" + r.Method)
		srv.httpMux.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()

	conn, _, err := rc.Hijack()
	if err != nil {
		slog.Error(fmt.Sprintf("hijack error: %v", err))
		return
	}

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}

	slog.Info(fmt.Sprintf("receive new http proxy TCP connection %s <---> %s", conn.RemoteAddr().String(), hostPort))

	rconn, err := srv.Dial("tcp", hostPort)
	if err != nil {
		return
	}
	defer rconn.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(rconn, conn)
		if cw, ok := rconn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	io.Copy(conn, rconn)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	<-done
}
