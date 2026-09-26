package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

type tlsServerResult struct {
	serverName         string
	supportedProtos    []string
	negotiatedProtocol string
	err                error
}

type connectUpstreamResult struct {
	serverName         string
	supportedProtos    []string
	negotiatedProtocol string
	request            []byte
	err                error
}

func serveConnectUpstream(conn net.Conn, cert tls.Certificate, results chan<- connectUpstreamResult) {
	serveConnectUpstreamWithCurves(conn, cert, nil, results)
}

func serveConnectUpstreamWithCurves(conn net.Conn, cert tls.Certificate, curves []tls.CurveID, results chan<- connectUpstreamResult) {
	helloInfo := make(chan struct {
		serverName      string
		supportedProtos []string
	}, 4)
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"h2", "http/1.1"},
		CurvePreferences: append([]tls.CurveID(nil), curves...),
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			helloInfo <- struct {
				serverName      string
				supportedProtos []string
			}{
				serverName:      hello.ServerName,
				supportedProtos: append([]string(nil), hello.SupportedProtos...),
			}
			return nil, nil
		},
	})
	defer tlsConn.Close()
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	info := <-helloInfo
	request := make([]byte, len("ping through tunnel"))
	if _, err := io.ReadFull(tlsConn, request); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}
	if _, err := tlsConn.Write([]byte("pong from upstream")); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	results <- connectUpstreamResult{
		serverName:         info.serverName,
		supportedProtos:    info.supportedProtos,
		negotiatedProtocol: tlsConn.ConnectionState().NegotiatedProtocol,
		request:            request,
	}
}

func receiveConnectUpstreamResult(t *testing.T, results <-chan connectUpstreamResult) connectUpstreamResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect upstream server")
	}
	return connectUpstreamResult{}
}

func newLocalTLSServer(t *testing.T, nextProtos []string) (net.Listener, <-chan tlsServerResult) {
	t.Helper()

	cert := localTLSCertificate(t)
	results := make(chan tlsServerResult, 1)
	helloInfo := make(chan struct {
		serverName      string
		supportedProtos []string
	}, 1)

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		baseListener.Close()
	})

	if tcpListener, ok := baseListener.(*net.TCPListener); ok {
		if err := tcpListener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}

	tlsListener := tls.NewListener(baseListener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			helloInfo <- struct {
				serverName      string
				supportedProtos []string
			}{
				serverName:      hello.ServerName,
				supportedProtos: append([]string(nil), hello.SupportedProtos...),
			}
			return nil, nil
		},
	})

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			results <- tlsServerResult{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			results <- tlsServerResult{err: err}
			return
		}

		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		result := tlsServerResult{err: err}
		if err == nil {
			info := <-helloInfo
			result.serverName = info.serverName
			result.supportedProtos = info.supportedProtos
			result.negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
		}
		results <- result
	}()

	return tlsListener, results
}

func receiveTLSServerResult(t *testing.T, results <-chan tlsServerResult) tlsServerResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for local TLS server")
	}
	return tlsServerResult{}
}

func TestRandomizedTLSProfileHandshakeModes(t *testing.T) {
	for _, test := range []struct {
		mode          string
		checkALPN     bool
		wantALPN      bool
		checkProtocol bool
		wantProtocol  bool
	}{
		{mode: tlsprofile.RandomizedALPNAuto},
		{mode: tlsprofile.RandomizedALPNRequired, checkALPN: true, wantALPN: true, checkProtocol: true, wantProtocol: true},
		{mode: tlsprofile.RandomizedALPNDisabled, checkALPN: true, checkProtocol: true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			listener, results := newLocalTLSServer(t, []string{"h2", "http/1.1"})
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			profile, err := tlsprofile.TemplateFromRandomized("random", test.mode)
			if err != nil {
				t.Fatal(err)
			}
			client, err := (&TunnelHandler{}).utlsWrapTemplate(conn, "upstream.test", []string{"h2", "http/1.1"}, profile)
			if err != nil {
				t.Fatalf("randomized handshake failed: %v", err)
			}
			_ = client.Close()
			server := receiveTLSServerResult(t, results)
			if server.err != nil {
				t.Fatalf("server handshake failed: %v", server.err)
			}
			if test.checkALPN && (len(server.supportedProtos) > 0) != test.wantALPN {
				t.Fatalf("offered ALPN = %v, wantALPN=%v", server.supportedProtos, test.wantALPN)
			}
			if test.checkProtocol && (server.negotiatedProtocol != "") != test.wantProtocol {
				t.Fatalf("negotiated ALPN = %q, wantProtocol=%v", server.negotiatedProtocol, test.wantProtocol)
			}
		})
	}
}

func newBadUpstreamServer(t *testing.T, handle func(net.Conn)) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
	})

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		if err := tcpListener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		handle(conn)
	}()

	return listener
}

func localTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"upstream.test"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse test TLS certificate: %v", err)
	}
	return cert
}
