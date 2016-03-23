package irc

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	e := Client{
		Hostname: "foo",
		Nickname: "bar",
		Username: "hello",
		RealName: "world",
	}

	got := *NewClient("foo", "bar", "hello", "world")
	cond := got.Hostname == e.Hostname && got.Nickname == e.Nickname &&
		got.Username == e.Username && got.RealName == e.RealName
	if !cond {
		t.Errorf("NewClient() == %q, want %q", e, got)
	}
}

func handleError(t *testing.T, err error, msg string) {
	if err == nil {
		return
	}

	t.Fatalf(msg, err)
}

func getClient(t *testing.T) (*net.TCPListener, *Client) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	handleError(t, err, "Error while creating address: %v")

	listener, err := net.ListenTCP("tcp", addr)
	handleError(t, err, "Error while creating listener: %v")
	listener.SetDeadline(time.Now().Add(1 * time.Second))

	clientAddr := listener.Addr().String()
	client := NewClient(clientAddr, "testa", "test_user", "A Tester")
	return listener, client
}

func longTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping, test might take a while.")
	}
}

func TestClientConnect(t *testing.T) {
	longTest(t)

	listener, client := getClient(t)
	client.Connect()
	defer client.Close()

	conn, err := listener.AcceptTCP()
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	handleError(t, err, "Error accepting TCP connection. "+
		"Client did probably not response. %v")

	expected := []string{"NICK testa", "USER test_user 0 * :A Tester"}
	scanner := bufio.NewScanner(conn)
	for i, line := range expected {
		if !scanner.Scan() {
			t.Errorf("Client sent too few lines (%v).", i)
		}

		if text := scanner.Text(); text != line {
			msg := "Client sent incorrect line: '%q', expected '%q.'"
			t.Errorf(msg, text, line)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Errorf("Scanner returned error: %v", err)
	}

	conn.Close()
}

func TestClientClose(t *testing.T) {
	conn, client := connectClient(t)
	if !client.Connected() {
		t.Error("Client returns it is not connected although the " +
			"TCP connection was already espablished.")
	}

	client.Close()
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		msg := "Connection still open expected to be closed. " +
			"Got error: %v instead."
		t.Errorf(msg, err)
	}

	if client.Connected() {
		t.Error("Connected still returns true, expected false.")
	}
}

func connectClient(t *testing.T) (*net.TCPConn, *Client) {
	longTest(t)

	listener, client := getClient(t)
	if client.Connected() {
		t.Error("Client returns its connected before Connect() as called")
	}

	client.Connect()

	conn, err := listener.AcceptTCP()
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	handleError(t, err, "Error accepting TCP connection. "+
		"probably did not responde. %v")

	hello := []byte("NICK testa" + CRLF + "USER test_user 0 * :A Tester" + CRLF)
	got := make([]byte, len(hello))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("Error while reading init message: %v", err)
	} else if !bytes.Equal(got, hello) {
		msg := "Expected to get: %q; got: %q"
		t.Fatalf(msg, string(hello), string(got))
	}

	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 250))
	return conn, client
}

func assertEndTransmition(t *testing.T, conn io.Reader) {
	scanner := bufio.NewScanner(conn)
	if b := scanner.Scan(); b {
		msg := "Expected connection to stop transmitting, got: %v"
		t.Errorf(msg, scanner.Text())
	} else if err, ok := scanner.Err().(net.Error); !ok || !err.Timeout() {
		msg := "Expected to get a timeout error, got: %v"
		t.Errorf(msg, scanner.Err())
	}
}

func TestSendMessage(t *testing.T) {
	conn, client := connectClient(t)
	client.SendMessage("hello world")
	client.SendMessage("does it work??")

	expected := []string{"hello world", "does it work??"}
	scanner := bufio.NewScanner(conn)
	for i, line := range expected {
		if !scanner.Scan() {
			t.Errorf("Scanner ended after %v iteration.", i)
			break
		}

		if scanner.Text() != line {
			msg := "Expected to transmite: %v; got: %v"
			t.Errorf(msg, line, scanner.Text())
		}
	}
	assertEndTransmition(t, conn)
}

func TestNewClientShort(t *testing.T) {
	n := "user_123"
	s := NewClientShort("host:321", n)
	cond := s.Hostname == "host:321" && s.Username == n &&
		s.RealName == n && s.Nickname == n

	if !cond {
		t.Errorf("Client hostname or user is incorrect. %v", s)
	}
}

func TestRegisterEvent(t *testing.T) {
	s := NewClientShort("localhost:1234", "user_123")
	s.RegisterEvent("PING", func(m string) bool { return false })

	if e := s.events["PING"]; len(e) != 1 || e[0] == nil {
		msg := "EventHandler added more handlers then expected. " +
			"Handlers: %v."
		t.Errorf(msg, e)
	}

	s.RegisterEvent("PING", func(m string) bool { return false })
	if e := s.events["PING"]; len(e) != 2 || e[0] == nil || e[1] == nil {
		msg := "EventHandler added more or less handlers then " +
			"expected. Handlers: %v."
		t.Errorf(msg, e)
	}
}

func TestFireEvent(t *testing.T) {
	msg := "PING say something"
	checkMsg := func(m string) {
		if m != msg {
			errorMsg := "Expected to get message: '%s', " +
				"got '%v' instead"
			t.Errorf(errorMsg, msg, m)
		}
	}

	fireCount := -1
	mk := func(r bool) EventCallback {
		return func(m string) bool {
			checkMsg(m)
			fireCount++
			return r
		}
	}

	testcase := []struct {
		handlers          []EventCallback
		expectedFirecount int
	}{
		{
			[]EventCallback{mk(false)}, 1,
		}, {
			[]EventCallback{mk(false), mk(false)}, 2,
		}, {
			[]EventCallback{mk(false), mk(true), mk(false)}, 2,
		}, {
			[]EventCallback{mk(false), mk(false), mk(false)}, 3,
		},
	}

	for _, test := range testcase {
		fireCount = 0
		s := NewClientShort("host:123", "user")
		for _, handler := range test.handlers {
			s.RegisterEvent("PING", handler)
		}

		s.FireEvent(msg)
		if fireCount != test.expectedFirecount {
			msg := "Expected %v events to get fired. %v were actually"
			t.Errorf(msg, test.expectedFirecount, fireCount)
		}
	}
}

func TestFireEventEmptyMessage(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected FireEvent(\"\") to panic")
		} else if r != "No message given" {
			t.Errorf("Unkown panic: %v", r)
		}
	}()

	NewClientShort("", "").FireEvent("")
}
