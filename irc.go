package irc

import (
	"net"
	"strings"
)

const (
	CRLF = "\r\n"
)

type EventCallback func(message string) bool

type Client struct {
	// The hostname and port formatted like this:
	// domain:port
	Hostname string

	Nickname string

	Username string

	RealName string

	socket *net.TCPConn

	events map[string][]EventCallback
}

func NewClient(hostname, nickname, username, realname string) *Client {
	return &Client{
		Hostname: hostname,
		Nickname: nickname,
		Username: username,
		RealName: realname,
		events:   make(map[string][]EventCallback),
	}
}

func NewClientShort(hostname, user string) *Client {
	return NewClient(hostname, user, user, user)
}

func (s *Client) Connect() error {
	addr, err := net.ResolveTCPAddr("tcp", s.Hostname)
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}

	s.socket = conn
	err = s.initiateConnection()
	return err
}

func (s *Client) RegisterEvent(name string, back EventCallback) {
	s.events[name] = append(s.events[name], back)
}

// FireEvent fires the event to all appropriate handlers. If no message is
// given (i.e. the message is empty), this function will panic because the
// message is expected to have content.
func (s *Client) FireEvent(message string) {
	if message == "" {
		panic("No message given")
	}

	event := strings.SplitN(message, " ", 2)[0]
	for _, handler := range s.events[event] {
		if handler(message) {
			return
		}
	}
}

func (s *Client) initiateConnection() error {
	if _, err := s.sendMessage("NICK", s.Nickname); err != nil {
		return err
	}

	_, err := s.sendMessage("USER", s.Username, "0", "*", ":"+s.RealName)
	return err
}

func (s *Client) sendMessage(params ...string) (int, error) {
	msg := strings.Join(params, " ")
	return s.socket.Write([]byte(msg + CRLF))
}

func (s *Client) Connected() bool {
	return s.socket != nil
}

func (s *Client) Close() error {
	if s.socket != nil {
		err := s.socket.Close()
		if err == nil {
			s.socket = nil
		}

		return err
	}

	return nil
}
