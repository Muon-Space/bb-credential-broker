package egressauthd

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// hopByHopHeaders are the HTTP/1.1 connection-scoped headers that must
// not be forwarded between the proxy's two connections (RFC 7230 §6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders strips connection-scoped headers from h before
// the request is re-issued to the upstream. Per RFC 7230 §6.1 this
// includes any header named in the request's own Connection header, not
// just the well-known set below.
func removeHopByHopHeaders(h http.Header) {
	for _, conn := range h.Values("Connection") {
		for _, name := range strings.Split(conn, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// copyHeader copies all values from src into dst.
func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// basicAuth encodes username:password as the base64 payload of a Basic
// Authorization header.
func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// writeRawResponse writes a minimal HTTP/1.1 response with a plain-text
// body directly to a hijacked connection. It is used on the MITM tunnel
// where there is no http.ResponseWriter to reject a request.
func writeRawResponse(w io.Writer, status int, body string) {
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "Error"
	}
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, statusText, len(body), body)
}
