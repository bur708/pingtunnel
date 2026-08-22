package pingtunnel

import (
	"bytes"
	"testing"
)

// fakeSocks5Conn glues a request-byte reader to a response-byte buffer so
// socks5ServerAuthHandshake can be driven without a real net.Conn.
type fakeSocks5Conn struct {
	*bytes.Reader
	out *bytes.Buffer
}

func (c *fakeSocks5Conn) Write(p []byte) (int, error) {
	return c.out.Write(p)
}

func newFakeSocks5Conn(clientBytes []byte) *fakeSocks5Conn {
	return &fakeSocks5Conn{Reader: bytes.NewReader(clientBytes), out: &bytes.Buffer{}}
}

func TestSocks5ServerAuthHandshakeNoAuthConfigured(t *testing.T) {
	// greeting: ver 5, 1 method, no-auth
	conn := newFakeSocks5Conn([]byte{0x05, 0x01, 0x00})
	if err := socks5ServerAuthHandshake(conn, "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(conn.out.Bytes(), []byte{0x05, socks5AuthNone}) {
		t.Fatalf("unexpected reply: %v", conn.out.Bytes())
	}
}

func TestSocks5ServerAuthHandshakeCorrectCredentials(t *testing.T) {
	// greeting: ver 5, 1 method, user/pass; then auth sub-negotiation
	client := []byte{0x05, 0x01, 0x02}
	client = append(client, 0x01, 0x04, 'a', 'l', 'i', 'c', 0x03, 'p', 'w', '1')
	conn := newFakeSocks5Conn(client)
	if err := socks5ServerAuthHandshake(conn, "alic", "pw1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x05, socks5AuthUserPass, socks5UserPassVersion, socks5AuthSuccess}
	if !bytes.Equal(conn.out.Bytes(), want) {
		t.Fatalf("unexpected reply: %v", conn.out.Bytes())
	}
}

// Regression test for the auth-bypass bug in gohome/network.Sock5HandshakeBy:
// that helper wrote the authFailure byte but still returned a nil error, so
// a client that ignored the failure byte and sent a request anyway was
// served regardless of credentials. This must return a non-nil error so the
// caller closes the connection instead of proceeding.
func TestSocks5ServerAuthHandshakeWrongCredentialsRejected(t *testing.T) {
	client := []byte{0x05, 0x01, 0x02}
	client = append(client, 0x01, 3, 'b', 'o', 'b', 1, 'x')
	conn := newFakeSocks5Conn(client)
	err := socks5ServerAuthHandshake(conn, "alice", "correct-password")
	if err == nil {
		t.Fatal("expected error for mismatched credentials, got nil")
	}
	want := []byte{0x05, socks5AuthUserPass, socks5UserPassVersion, socks5AuthFailure}
	if !bytes.Equal(conn.out.Bytes(), want) {
		t.Fatalf("unexpected reply: %v", conn.out.Bytes())
	}
}

func TestReadSocks5RequestConnect(t *testing.T) {
	reqBytes := []byte{
		0x05, 0x01, 0x00, 0x03, 0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	}

	req, err := readSocks5Request(bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("readSocks5Request failed: %v", err)
	}
	if req.Command != socks5CmdConnect {
		t.Fatalf("unexpected command: %d", req.Command)
	}
	if req.Address != "example.com:443" {
		t.Fatalf("unexpected address: %s", req.Address)
	}
}

func TestReadSocks5RequestUDPAssociate(t *testing.T) {
	reqBytes := []byte{
		0x05, 0x03, 0x00, 0x01,
		127, 0, 0, 1,
		0xd4, 0x31, // 54321
	}

	req, err := readSocks5Request(bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("readSocks5Request failed: %v", err)
	}
	if req.Command != socks5CmdUDPAssociate {
		t.Fatalf("unexpected command: %d", req.Command)
	}
	if req.Address != "127.0.0.1:54321" {
		t.Fatalf("unexpected address: %s", req.Address)
	}
}

func TestReadSocks5RequestInvalidVersion(t *testing.T) {
	reqBytes := []byte{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35}
	_, err := readSocks5Request(bytes.NewReader(reqBytes))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestSocks5UDPDatagramRoundTrip(t *testing.T) {
	target := "8.8.8.8:53"
	payload := []byte{0xde, 0xad, 0xbe, 0xef}

	packet, err := buildSocks5UDPDatagram(target, payload)
	if err != nil {
		t.Fatalf("buildSocks5UDPDatagram failed: %v", err)
	}

	parsedTarget, parsedPayload, err := parseSocks5UDPDatagram(packet)
	if err != nil {
		t.Fatalf("parseSocks5UDPDatagram failed: %v", err)
	}
	if parsedTarget != target {
		t.Fatalf("unexpected target: %s", parsedTarget)
	}
	if !bytes.Equal(parsedPayload, payload) {
		t.Fatalf("unexpected payload: %v", parsedPayload)
	}
}

func TestSocks5UDPDatagramRejectFragment(t *testing.T) {
	packet := []byte{
		0x00, 0x00, 0x01, // FRAG != 0
		0x01, 1, 1, 1, 1, 0x00, 0x35,
		0xaa,
	}

	_, _, err := parseSocks5UDPDatagram(packet)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
