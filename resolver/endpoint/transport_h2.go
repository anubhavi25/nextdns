package endpoint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
)

type transport struct {
	http.RoundTripper
	hostname string
	path     string
	addr     string
}

func newTransportH2(e *DOHEndpoint, addrs []string) http.RoundTripper {
	d := &parallelDialer{}
	d.FallbackDelay = -1 // disable happy eyeball, we do our own
	var t http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         e.Hostname,
			RootCAs:            getRootCAs(),
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
		DialContext: func(ctx context.Context, network, _ string) (c net.Conn, err error) {
			return d.DialParallel(ctx, network, addrs)
		},
		ForceAttemptHTTP2: true,
	}
	runtime.SetFinalizer(t, func(t *http.Transport) {
		t.CloseIdleConnections()
	})
	if e.onConnect != nil {
		t = roundTripperConnectTracer{
			RoundTripper: t,
			OnConnect:    e.onConnect,
		}
	}
	return t
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = t.addr
	req.Host = t.hostname
	if t.path != "" {
		req.URL.Path = t.path
	}
	return t.RoundTripper.RoundTrip(req)
}

func endpointAddrs(e *DOHEndpoint) (addrs []string) {
	if len(e.Bootstrap) != 0 {
		for _, addr := range e.Bootstrap {
			addrs = append(addrs, net.JoinHostPort(addr, "443"))
		}
	} else {
		addrs = []string{net.JoinHostPort(e.Hostname, "443")}
	}
	return addrs
}
