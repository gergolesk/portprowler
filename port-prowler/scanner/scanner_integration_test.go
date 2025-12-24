package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPScan_OpenAndClosed(t *testing.T) {
	// start a listener to get an open port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	portNum := uint16(addr.Port)

	// perform open scan
	res := TCPScan(context.Background(), "127.0.0.1", portNum, 1*time.Second, false)
	if res.State != "open" {
		t.Fatalf("expected open, got %s (err=%s)", res.State, res.Error)
	}

	// close listener to make the port closed (connection refused)
	_ = l.Close()

	// small sleep to allow OS to release socket
	time.Sleep(50 * time.Millisecond)

	res2 := TCPScan(context.Background(), "127.0.0.1", portNum, 500*time.Millisecond, false)
	if !(res2.State == "closed" || res2.State == "filtered") {
		t.Fatalf("expected closed or filtered after close, got %s (err=%s)", res2.State, res2.Error)
	}
}

func TestUDPScan_Open(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	portNum := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	// spawn responder
	go func() {
		buf := make([]byte, 1500)
		n, raddr, _ := conn.ReadFromUDP(buf)
		// echo something back
		if n > 0 && raddr != nil {
			_, _ = conn.WriteToUDP([]byte("pong"), raddr)
		}
	}()

	res := UDPScan(context.Background(), "127.0.0.1", portNum, 1*time.Second, false)
	if res.State != "open" {
		t.Fatalf("expected udp open, got %s (err=%s)", res.State, res.Error)
	}
}
