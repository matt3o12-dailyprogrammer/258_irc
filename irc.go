package irc

import (
	"bufio"
	"log"
	"net"
	"strings"
	"sync"
)

const (
	CRLF = "\r\n"
)

// Called when a new event is fired (e.g. a message is recieved
type EventCallback func(message string) bool

// The Client that containing the usernames, hostname, socket (if connected)
// and events.
type Client struct {
	// The hostname and port formatted like this:
	// domain:port
	Hostname    string
	Nickname    string
	Username    string
	RealName    string
	socket      *net.TCPConn
	events      map[string][]EventCallback
	lastErr     error
	sendCh      chan string
	closeSendCh chan bool

	eventLock   sync.RWMutex
	connectLock sync.Mutex
}

// NewClient returns a new client, with an inizilized events map, and the given
// names.
func NewClient(hostname, nickname, username, realname string) *Client {
	return &Client{
		Hostname: hostname,
		Nickname: nickname,
		Username: username,
		RealName: realname,
		events:   make(map[string][]EventCallback),
	}
}

// NewClientShort creates a new client but uses user name for the nickname
// username, and realname.
func NewClientShort(hostname, user string) *Client {
	return NewClient(hostname, user, user, user)
}

func (c *Client) messageReceiver(ready chan bool) {
	scanner := bufio.NewScanner(c.socket)
	ready <- true
	for scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			c.FireEvent(t)
		}
	}

	// There was an error and the server is not closed.
	if err := scanner.Err(); err != nil && c.Connected() {
		c.closeError(err)
	}
}

func (s *Client) messageListener() {
	for {
		select {
		case <-s.closeSendCh:
			return

		case msg := <-s.sendCh:
			if _, err := s.sendMessage(msg); err != nil {
				s.closeError(err)
			}

		}
	}
}

// Connects to the IRC server. Returns network errors if any occured.
func (s *Client) Connect() error {
	s.connectLock.Lock()
	defer s.connectLock.Unlock()

	addr, err := net.ResolveTCPAddr("tcp", s.Hostname)
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}

	s.socket = conn
	if err := s.initiateConnection(); err != nil {
		return err
	}

	s.sendCh = make(chan string)
	s.closeSendCh = make(chan bool)
	s.RegisterEvent("PING", s.pingResponder)
	ready := make(chan bool)
	go s.messageListener()
	go s.messageReceiver(ready)
	<-ready
	return nil
}

func (c *Client) pingResponder(m string) bool {
	message := m[5:] // 'PING ' is 5 characters
	c.SendMessage("PONG " + message)

	return true
}

// RegisterEvent registers a new event
func (s *Client) RegisterEvent(name string, back EventCallback) {
	s.eventLock.Lock()
	s.events[name] = append(s.events[name], back)
	s.eventLock.Unlock()
}

// SendMessage schedules a message to get sent.
// This method will panic if the server is not connected.
// There is no garantuee that the message is actually sent because
// the channel might have been closed. In that case, Client.Err()
// will return the latest error. Client.Err() might not be available
// immediately.
func (c *Client) SendMessage(message string) {
	if c.Connected() {
		c.sendCh <- message
	} else {
		panic("Server not connected")
	}
}

// Err returns the last error that occured while sending a message.
func (c *Client) Err() error {
	return c.lastErr
}

// FireEvent fires the event to all appropriate handlers. If no message is
// given (i.e. the message is empty), this function will panic because the
// message is expected to have content.
func (s *Client) FireEvent(message string) {
	if message == "" {
		panic("No message given")
	}

	event := strings.SplitN(message, " ", 2)[0]
	s.eventLock.RLock()
	defer s.eventLock.RUnlock()
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

// Connected returns true when the server is connected. Warning: the server
// might already have dropped the connection but the TCP connections is still
// valid (because a read hasn't been called). In this case, this method will
// return false.
func (s *Client) Connected() bool {
	return s.socket != nil
}

func (c *Client) closeError(err error) {
	log.Printf("Shutting down due to error: %q.\n", err)
	c.lastErr = err
	if err := c.Close(); err != nil {
		log.Printf("While shutting down, another error occured: %q\n", err)
	}
}

// Close tries to close the TCP connection. If there was an error, the
// connection is left as the TCP socket left it.
func (s *Client) Close() error {
	s.connectLock.Lock()
	defer s.connectLock.Unlock()

	if s.socket != nil {
		err := s.socket.Close()
		if err == nil {
			s.closeSendCh <- true
			s.socket = nil
		}

		return err
	}

	return nil
}
