package endpoint

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"time"
)

type ConnectInfo struct {
	ConnectStatus      string
	ServerAddr         string
	ConnectTime        time.Duration
	Protocol           string
	TLSTime            time.Duration
	TLSVersion         string
	TLSALPNProtocol    string
	TLSCipherSuiteName string
	TLSSNIExtAddr      string
	TLSHandshakeStatus string
}

func withConnectInfo(ctx context.Context) (context.Context, *ConnectInfo) {
	ci := &ConnectInfo{Protocol: "TCP"}
	var connectStart time.Time
	var tlsStart time.Time
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				ci.ConnectStatus = err.Error()
			} else {
				ci.ConnectStatus = "ok"
			}
			ci.ConnectTime = time.Since(connectStart)
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				ci.TLSHandshakeStatus = err.Error()
			} else {
				ci.TLSHandshakeStatus = "ok"
			}
			ci.TLSTime = time.Since(tlsStart)
			ci.TLSVersion = tlsVersion(cs.Version)
			ci.TLSALPNProtocol = cs.NegotiatedProtocol
			ci.TLSCipherSuiteName = tls.CipherSuiteName(cs.CipherSuite)
			ci.TLSSNIExtAddr = cs.ServerName
		},
		GotConn: func(hci httptrace.GotConnInfo) {
			if hci.Conn != nil {
				ci.ServerAddr = hci.Conn.RemoteAddr().String()
			}
			if hci.Reused {
				return
			}
		},
	}), ci
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}

type roundTripperConnectTracer struct {
	http.RoundTripper
	OnConnect func(*ConnectInfo)
}

func (rt roundTripperConnectTracer) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	ctx, ci := withConnectInfo(req.Context())
	req = req.WithContext(ctx)
	resp, err = rt.RoundTripper.RoundTrip(req)
	if ci.ConnectStatus == "ok" {
		rt.OnConnect(ci)
	}
	return resp, err
}
