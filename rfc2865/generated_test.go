package rfc2865

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/holgermetschulat/radius"
)

type TestServer struct {
	Addr     string
	Server   *radius.PacketServer
	l        net.PacketConn
	serveErr error
}

func (s *TestServer) Close() error {
	return s.l.Close()
}

func NewTestServer(handler radius.Handler, secretSource radius.SecretSource) *TestServer {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	s := &TestServer{
		Addr: conn.LocalAddr().String(),
		Server: &radius.PacketServer{
			Handler:      handler,
			SecretSource: secretSource,
		},
		l: conn,
	}

	go func() {
		s.serveErr = s.Server.Serve(s.l)
	}()

	return s
}

func TestClientEncryption(t *testing.T) {
	secret := []byte(`12345`)
	expectedPassword := "testsecret"

	handler := radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		resp := r.Response(radius.CodeAccessAccept)
		password := UserPassword_GetString(r.Packet)
		if password != expectedPassword {
			t.Fatalf("incorrect password: expected %v, got %v", expectedPassword, password)
		}
		err := w.Write(resp)
		if err != nil {
			t.Fatal(err)
		}
	})

	server := NewTestServer(handler, radius.StaticSecretSource(secret))
	defer server.Close()

	req := radius.New(radius.CodeAccessRequest, secret)
	err := UserPassword_SetString(req, expectedPassword)
	if err != nil {
		t.Fatalf("Exchange error %v", err)
	}

	client := radius.Client{
		Retry:           time.Millisecond * 50,
		MaxPacketErrors: 2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = client.Exchange(ctx, req, server.Addr)
	if err != nil {
		t.Fatalf("Exchange error %v", err)
	}
}
