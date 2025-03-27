package ttproxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// only handle HTTP CONNNECT method
	// ignore other HTTP method
	if r.Method != http.MethodConnect {
		// slog.Error("http method error: %v" + r.Method)
		srv.httpMux.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	err := rc.Flush()
	if err != nil {
		slog.Error(fmt.Sprintf("flush response writer error: %v", err))
		return
	}

	conn, bfw, err := rc.Hijack()
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

	// write all buffered bytes into remote connection
	if n := bfw.Reader.Buffered(); n > 0 {
		bb, err := bfw.Reader.Peek(n)
		if err != nil {
			return
		}

		_, err = rconn.Write(bb)
		if err != nil {
			return
		}
	}

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
