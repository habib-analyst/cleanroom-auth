// Package logmw is cleanroom-auth's logging middleware: every request and
// response body passes through the PII redactor before it touches the log
// sink, so the log file structurally cannot contain the PII classes the
// redactor knows — a property the breach suite verifies by grepping the
// actual log output for planted values.
package logmw

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"cleanroom/internal/redact"
)

// Logger writes redacted log lines to a sink. Safe for concurrent use.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
	Now func() time.Time
}

func New(out io.Writer) *Logger {
	return &Logger{out: out, Now: time.Now}
}

func (l *Logger) logf(format string, args ...any) {
	clean, _ := redact.Redact(fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.out, clean+"\n")
}

// Middleware logs method, path, status, and the request/response bodies
// (redacted). Bodies are restored for downstream handlers.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		rec := &recorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		l.logf("%s %s -> %d req=%s resp=%s",
			r.Method, r.URL.RequestURI(), rec.status,
			string(reqBody), rec.buf.String())
	})
}

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rc *recorder) WriteHeader(status int) {
	rc.status = status
	rc.ResponseWriter.WriteHeader(status)
}

func (rc *recorder) Write(b []byte) (int, error) {
	rc.buf.Write(b)
	return rc.ResponseWriter.Write(b)
}
