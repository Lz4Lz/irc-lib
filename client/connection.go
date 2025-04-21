package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	sasl "github.com/emersion/go-sasl"
	"github.com/lz4lz/irc-lib/logging"
	"github.com/lz4lz/irc-lib/state"
	"golang.org/x/net/proxy"
)

// Connection encapsulates a connection to a single IRC server.
// One can be created with Client or SimpleClient.
type Connection struct {
	// For preventing race conditions on (dis)connect.
	mu sync.RWMutex

	// Contains parameters that people can tweak to change client behavior.
	cfg *ClientConfig

	// Handlers
	internalHandlers   *hSet
	foregroundHandlers *hSet
	backgroundHandlers *hSet

	// State tracker for nicks and channels.
	st         state.Tracker
	stRemovers []Remover

	// I/O stuff to server.
	dialer      *net.Dialer
	proxyDialer proxy.Dialer
	sock        net.Conn
	io          *bufio.ReadWriter
	in          chan *Line
	out         chan string
	connected   bool

	// Capabilities supported by the server.
	supportedCaps *capSet

	// Capabilities that are currently enabled.
	currentCaps *capSet

	// SASL internals stuff.
	saslRemainingData []byte

	// CancelFunc and WaitGroup for goroutines.
	die context.CancelFunc
	wg  sync.WaitGroup

	// Internal counters for flood protection.
	badness  time.Duration
	lastSent time.Time
}

// ClientConfig contains options that can be passed to Client to change the
// behavior of the library during use. It is recommended that NewClientConfig
// is used to create this struct rather than instantiating one directly.
// Passing a ClientConfig with no Nick in the Me field to Client will result
// in unflattering consequences.
type ClientConfig struct {
	// Set this to provide the Nick, Ident and Name for the client to use.
	// It is recommended to call Connection.Me to get up-to-date information
	// about the current state of the client's IRC nick after connecting.
	// This is because the nick might be dynamically updated to account
	// for occupied nicks.
	Me *state.Nick

	// Hostname to connect to and optional connect password.
	// Changing these after connection will have no effect until the
	// client reconnects.
	Server, Pass string

	// Are we connecting via SSL? Do we care about certificate validity?
	// Changing these after connection will have no effect until the
	// client reconnects.
	SSL       bool
	SSLConfig *tls.Config

	// To connect via proxy set the proxy url here.
	// Changing these after connection will have no effect until the
	// client reconnects.
	Proxy string

	// Local address to bind to when connecting to the server.
	LocalAddr string

	// To attempt RFC6555 parallel IPv4 and IPv6 connections if both
	// address families are returned for a hostname, set this to true.
	// Passed through to https://golang.org/pkg/net/#Dialer
	DualStack bool

	// Enable IRCv3 capability negotiation.
	EnableCapabilityNegotiation bool

	// A list of capabilities to request to the server during registration.
	Capabilities []string

	// SASL configuration to use to authenticate the connection.
	Sasl sasl.Client

	// Replaceable function to customise the 433 handler's new nick.
	// By default the current nick's last character is "incremented".
	// See DefaultNewNick implementation below for details.
	NewNick func(string) string

	// Client->server ping frequency, in seconds. Defaults to 3m.
	// Set to 0 to disable client-side pings.
	PingFreq time.Duration

	// The duration before a connection timeout is triggered. Defaults to 1m.
	// Set to 0 to wait indefinitely.
	Timeout time.Duration

	// Set this to true to disable flood protection and false to re-enable.
	Flood bool

	// Sent as the reply to a CTCP VERSION message.
	Version string

	// Sent as the default QUIT message if Quit is called with no args.
	QuitMessage string

	// Configurable panic recovery for all handlers.
	// Defaults to logging an error, see LogPanic.
	Recover func(*Connection, *Line)

	// Split PRIVMSGs, NOTICEs and CTCPs longer than SplitLen characters
	// over multiple lines. Default to 450 if not set.
	SplitLen int
}

// NewClientConfig creates a ClientConfig struct containing sensible defaults.
// It takes one required argument: the nick to use for the client.
// Subsequent string arguments set the client's ident and "real"
// name, but these are optional.
func NewClientConfig(nick string, args ...string) *ClientConfig {
	cfg := &ClientConfig{
		Me:                          &state.Nick{Nick: nick},
		PingFreq:                    3 * time.Minute,
		NewNick:                     DefaultNewNick,
		Recover:                     (*Connection).LogPanic, // in dispatch.go
		SplitLen:                    defaultSplit,
		Timeout:                     60 * time.Second,
		EnableCapabilityNegotiation: false,
	}
	cfg.Me.Ident = "irclib"
	if len(args) > 0 && args[0] != "" {
		cfg.Me.Ident = args[0]
	}
	cfg.Me.Name = "GoIRCLibClient"
	if len(args) > 1 && args[1] != "" {
		cfg.Me.Name = args[1]
	}
	cfg.Version = "GoIRCLibClient"
	cfg.QuitMessage = "Goodbye!"
	return cfg
}

// Because networks limit nick lengths, the easy approach of appending
// an '_' to a nick that is already in use can cause problems. When the
// length limit is reached, the clients idea of what its nick is
// ends up being different from the server. Hilarity ensues.
// Thanks to github.com/purpleidea for the bug report!
// Thanks to 'man ascii' for
func DefaultNewNick(old string) string {
	if len(old) == 0 {
		return "_"
	}
	c := old[len(old)-1]
	switch {
	case c >= '0' && c <= '9':
		c = '0' + (((c - '0') + 1) % 10)
	case c >= 'A' && c <= '}':
		c = 'A' + (((c - 'A') + 1) % 61)
	default:
		c = '_'
	}
	return old[:len(old)-1] + string(c)
}

// SimpleClient creates a new Conn, passing its arguments to NewConfig.
// If you don't need to change any client options and just want to get
// started quickly, this is a convenient shortcut.
func SimpleClient(nick string, args ...string) *Connection {
	conn := Client(NewClientConfig(nick, args...))
	return conn
}

// Client takes a Config struct and returns a new Conn ready to have
// handlers added and connect to a server.
func Client(cfg *ClientConfig) *Connection {
	if cfg == nil {
		cfg = NewClientConfig("__undefined__")
	}
	if cfg.Me == nil || cfg.Me.Nick == "" || cfg.Me.Ident == "" {
		cfg.Me = &state.Nick{Nick: "__undefined__"}
		cfg.Me.Ident = "irclib"
		cfg.Me.Name = "GoIRCLibClient"
	}

	dialer := new(net.Dialer)
	dialer.Timeout = cfg.Timeout
	dialer.DualStack = cfg.DualStack
	if cfg.LocalAddr != "" {
		if !hasPort(cfg.LocalAddr) {
			cfg.LocalAddr += ":0"
		}

		local, err := net.ResolveTCPAddr("tcp", cfg.LocalAddr)
		if err == nil {
			dialer.LocalAddr = local
		} else {
			logging.Error("irc.Client(): Cannot resolve local address %s: %s", cfg.LocalAddr, err)
		}
	}

	if cfg.Sasl != nil && !cfg.EnableCapabilityNegotiation {
		logging.Warn("Enabling capability negotiation as it's required for SASL")
		cfg.EnableCapabilityNegotiation = true
	}

	conn := &Connection{
		cfg:                cfg,
		dialer:             dialer,
		internalHandlers:   handlerSet(),
		foregroundHandlers: handlerSet(),
		backgroundHandlers: handlerSet(),
		stRemovers:         make([]Remover, 0, len(stateHandlers)),
		lastSent:           time.Now(),
		supportedCaps:      capabilitySet(),
		currentCaps:        capabilitySet(),
		saslRemainingData:  nil,
	}
	conn.addIntHandlers()
	return conn
}

// Connected returns true if the client is successfully connected to
// an IRC server. It becomes true when the TCP connection is established,
// and false again when the connection is closed.
func (conn *Connection) Connected() bool {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	return conn.connected
}

// Config returns a pointer to the Config struct used by the client.
// Many of the elements of Config may be changed at any point to
// affect client behavior. To disable flood protection temporarily,
// for example, a handler could do:
//
//	conn.Config().Flood = true
//	// Send many lines to the IRC server, risking "excess flood"
//	conn.Config().Flood = false
func (conn *Connection) Config() *ClientConfig {
	return conn.cfg
}

// Me returns a state.Nick that reflects the client's IRC nick at the
// time it is called. If state tracking is enabled, this comes from
// the tracker, otherwise it is equivalent to conn.cfg.Me.
func (conn *Connection) Me() *state.Nick {
	if conn.st != nil {
		conn.cfg.Me = conn.st.Me()
	}
	return conn.cfg.Me
}

// StateTracker returns the state tracker being used by the client,
// if tracking is enabled, and nil otherwise.
func (conn *Connection) StateTracker() state.Tracker {
	return conn.st
}

// EnableStateTracking causes the client to track information about
// all channels it is joined to, and all the nicks in those channels.
// This can be rather handy for a number of bot-writing tasks. See
// the state package for more details.
//
// NOTE: Calling this while connected to an IRC server may cause the
// state tracker to become very confused all over STDERR if logging
// is enabled. State tracking should enabled before connecting or
// at a pinch while the client is not joined to any channels.
func (conn *Connection) EnableStateTracking() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.st == nil {
		n := conn.cfg.Me
		conn.st = state.NewTracker(n.Nick)
		conn.st.NickInfo(n.Nick, n.Ident, n.Host, n.Name)
		conn.cfg.Me = conn.st.Me()
		conn.addSTHandlers()
	}
}

// DisableStateTracking causes the client to stop tracking information
// about the channels and nicks it knows of. It will also wipe current
// state from the state tracker.
func (conn *Connection) DisableStateTracking() {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.st != nil {
		conn.cfg.Me = conn.st.Me()
		conn.delSTHandlers()
		conn.st.Wipe()
		conn.st = nil
	}
}

// SupportsCapability returns true if the server supports the given capability.
func (conn *Connection) SupportsCapability(cap string) bool {
	return conn.supportedCaps.Has(cap)
}

// HasCapability returns true if the given capability has been acked by the server during negotiation.
func (conn *Connection) HasCapability(cap string) bool {
	return conn.currentCaps.Has(cap)
}

// Per-connection state initialization.
func (conn *Connection) initialize() {
	conn.io = nil
	conn.sock = nil
	conn.in = make(chan *Line, 32)
	conn.out = make(chan string, 32)
	conn.die = nil
	if conn.st != nil {
		conn.st.Wipe()
	}
}

// ConnectTo connects the IRC client to "host[:port]", which should be either
// a hostname or an IP address, with an optional port. It sets the client's
// Config.Server to host, Config.Pass to pass if one is provided, and then
// calls Connect.
func (conn *Connection) ConnectTo(host string, pass ...string) error {
	return conn.ConnectToContext(context.Background(), host, pass...)
}

// ConnectToContext works like ConnectTo but uses the provided context.
func (conn *Connection) ConnectToContext(ctx context.Context, host string, pass ...string) error {
	conn.cfg.Server = host
	if len(pass) > 0 {
		conn.cfg.Pass = pass[0]
	}
	return conn.ConnectContext(ctx)
}

// Connect connects the IRC client to the server configured in Config.Server.
// To enable explicit SSL on the connection to the IRC server, set Config.SSL
// to true before calling Connect(). The port will default to 6697 if SSL is
// enabled, and 6667 otherwise.
// To enable connecting via a proxy server, set Config.Proxy to the proxy URL
// (example socks5://localhost:9000) before calling Connect().
//
// Upon successful connection, Connected will return true and a REGISTER event
// will be fired. This is mostly for internal use; it is suggested that a
// handler for the CONNECTED event is used to perform any initial client work
// like joining channels and sending messages.
func (conn *Connection) Connect() error {
	return conn.ConnectContext(context.Background())
}

// ConnectContext works like Connect but uses the provided context.
func (conn *Connection) ConnectContext(ctx context.Context) error {
	// We don't want to hold conn.mu while firing the REGISTER event,
	// and it's much easier and less error prone to defer the unlock,
	// so the connect mechanics have been delegated to internalConnect.
	err := conn.internalConnect(ctx)
	if err == nil {
		conn.dispatch(&Line{Cmd: REGISTER, Time: time.Now()})
	}
	return err
}

// internalConnect handles the work of actually connecting to the server.
func (conn *Connection) internalConnect(ctx context.Context) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.initialize()

	if conn.cfg.Server == "" {
		return fmt.Errorf("irc.Connect(): cfg.Server must be non-empty")
	}
	if conn.connected {
		return fmt.Errorf("irc.Connect(): Cannot connect to %s, already connected", conn.cfg.Server)
	}

	if !hasPort(conn.cfg.Server) {
		if conn.cfg.SSL {
			conn.cfg.Server = net.JoinHostPort(conn.cfg.Server, "6697")
		} else {
			conn.cfg.Server = net.JoinHostPort(conn.cfg.Server, "6667")
		}
	}

	if conn.cfg.Proxy != "" {
		s, err := conn.dialProxy(ctx)
		if err != nil {
			logging.Info("irc.Connect(): Connecting via proxy %q: %v",
				conn.cfg.Proxy, err)
			return err
		}
		conn.sock = s
	} else {
		logging.Info("irc.Connect(): Connecting to %s.", conn.cfg.Server)
		if s, err := conn.dialer.DialContext(ctx, "tcp", conn.cfg.Server); err == nil {
			conn.sock = s
		} else {
			return err
		}
	}

	if conn.cfg.SSL {
		logging.Info("irc.Connect(): Performing SSL handshake.")
		s := tls.Client(conn.sock, conn.cfg.SSLConfig)
		if err := s.Handshake(); err != nil {
			return err
		}
		conn.sock = s
	}

	conn.postConnect(ctx, true)
	conn.connected = true
	return nil
}

// dialProxy handles dialling via a proxy
func (conn *Connection) dialProxy(ctx context.Context) (net.Conn, error) {
	proxyURL, err := url.Parse(conn.cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %v", err)
	}
	proxyDialer, err := proxy.FromURL(proxyURL, conn.dialer)
	if err != nil {
		return nil, fmt.Errorf("creating dialer: %v", err)
	}
	conn.proxyDialer = proxyDialer
	contextProxyDialer, ok := proxyDialer.(proxy.ContextDialer)
	if ok {
		logging.Info("irc.Connect(): Connecting to %s.", conn.cfg.Server)
		return contextProxyDialer.DialContext(ctx, "tcp", conn.cfg.Server)
	} else {
		logging.Warn("Dialer for proxy does not support context, please implement DialContext")
		logging.Info("irc.Connect(): Connecting to %s.", conn.cfg.Server)
		return conn.proxyDialer.Dial("tcp", conn.cfg.Server)
	}
}

// postConnect performs post-connection setup, for ease of testing.
func (conn *Connection) postConnect(ctx context.Context, start bool) {
	conn.io = bufio.NewReadWriter(
		bufio.NewReader(conn.sock),
		bufio.NewWriter(conn.sock))
	if start {
		ctx, conn.die = context.WithCancel(ctx)
		conn.wg.Add(3)
		go conn.send(ctx)
		go conn.recv()
		go conn.runLoop(ctx)
		if conn.cfg.PingFreq > 0 {
			conn.wg.Add(1)
			go conn.ping(ctx)
		}
	}
}

// hasPort returns true if the string hostname has a :port suffix.
// It was copied from net/http for great justice.
func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

// send is started as a goroutine after a connection is established.
// It shuttles data from the output channel to write(), and is killed
// when the context is cancelled.
func (conn *Connection) send(ctx context.Context) {
	for {
		select {
		case line := <-conn.out:
			if err := conn.write(line); err != nil {
				logging.Error("irc.send(): %s", err.Error())
				// We can't defer this, because Close() waits for it.
				conn.wg.Done()
				conn.Close()
				return
			}
		case <-ctx.Done():
			// control channel closed, bail out
			conn.wg.Done()
			return
		}
	}
}

// recv is started as a goroutine after a connection is established.
// It receives "\r\n" terminated lines from the server, parses them into
// Lines, and sends them to the input channel.
func (conn *Connection) recv() {
	for {
		s, err := conn.io.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logging.Error("irc.recv(): %s", err.Error())
			}
			// We can't defer this, because Close() waits for it.
			conn.wg.Done()
			conn.Close()
			return
		}
		s = strings.Trim(s, "\r\n")
		logging.Debug("<- %s", s)

		if line := ParseLine(s); line != nil {
			line.Time = time.Now()
			conn.in <- line
		} else {
			logging.Warn("irc.recv(): problems parsing line:\n  %s", s)
		}
	}
}

// ping is started as a goroutine after a connection is established, as
// long as Config.PingFreq >0. It pings the server every PingFreq seconds.
func (conn *Connection) ping(ctx context.Context) {
	defer conn.wg.Done()
	tick := time.NewTicker(conn.cfg.PingFreq)
	for {
		select {
		case <-tick.C:
			conn.Ping(fmt.Sprintf("%d", time.Now().UnixNano()))
		case <-ctx.Done():
			// control channel closed, bail out
			tick.Stop()
			return
		}
	}
}

// runLoop is started as a goroutine after a connection is established.
// It pulls Lines from the input channel and dispatches them to any
// handlers that have been registered for that IRC verb.
func (conn *Connection) runLoop(ctx context.Context) {
	for {
		select {
		case line := <-conn.in:
			conn.dispatch(line)
		case <-ctx.Done():
			// control channel closed, trigger Cancel() to clean
			// things up properly and bail out

			// We can't defer this, because Close() waits for it.
			conn.wg.Done()
			conn.Close()
			return
		}
	}
}

// write writes a \r\n terminated line of output to the connected server,
// using Hybrid's algorithm to rate limit if conn.cfg.Flood is false.
func (conn *Connection) write(line string) error {
	if !conn.cfg.Flood {
		if t := conn.rateLimit(len(line)); t != 0 {
			// sleep for the current line's time value before sending it
			logging.Info("irc.rateLimit(): Flood! Sleeping for %.2f secs.",
				t.Seconds())
			<-time.After(t)
		}
	}

	if _, err := conn.io.WriteString(line + "\r\n"); err != nil {
		return err
	}
	if err := conn.io.Flush(); err != nil {
		return err
	}
	if strings.HasPrefix(line, "PASS") {
		line = "PASS **************"
	}
	logging.Debug("-> %s", line)
	return nil
}

// rateLimit implements Hybrid's flood control algorithm for outgoing lines.
func (conn *Connection) rateLimit(chars int) time.Duration {
	// Hybrid's algorithm allows for 2 seconds per line and an additional
	// 1/120 of a second per character on that line.
	lineTime := 2*time.Second + time.Duration(chars)*time.Second/120
	elapsed := time.Now().Sub(conn.lastSent)
	if conn.badness += lineTime - elapsed; conn.badness < 0 {
		// negative badness times are badness...
		conn.badness = 0
	}
	conn.lastSent = time.Now()
	// If we've sent more than 10 second's worth of lines according to the
	// calculation above, then we're at risk of "Excess Flood".
	if conn.badness > 10*time.Second {
		return lineTime
	}
	return 0
}

// Close tears down all connection-related state. It is called when either
// the sending or receiving goroutines encounter an error.
// It may also be used to forcibly shut down the connection to the server.
func (conn *Connection) Close() error {
	// Guard against double-call of Close() if we get an error in send()
	// as calling sock.Close() will cause recv() to receive EOF in readstring()
	conn.mu.Lock()
	if !conn.connected {
		conn.mu.Unlock()
		return nil
	}
	logging.Info("irc.Close(): Disconnected from server.")
	conn.connected = false
	err := conn.sock.Close()
	if conn.die != nil {
		conn.die()
	}
	// Drain both in and out channels to avoid a deadlock if the buffers
	// have filled. See TestSendDeadlockOnFullBuffer in connection_test.go.
	conn.drainIn()
	conn.drainOut()
	conn.wg.Wait()
	conn.mu.Unlock()
	// Dispatch after closing connection but before reinit
	// so event handlers can still access state information.
	conn.dispatch(&Line{Cmd: DISCONNECTED, Time: time.Now()})
	return err
}

// drainIn sends all data buffered in conn.in to /dev/null.
func (conn *Connection) drainIn() {
	for {
		select {
		case <-conn.in:
		default:
			return
		}
	}
}

// drainOut does the same for conn.out. Generics!
func (conn *Connection) drainOut() {
	for {
		select {
		case <-conn.out:
		default:
			return
		}
	}
}

// Dumps a load of information about the current state of the connection to a
// string for debugging state tracking and other such things.
func (conn *Connection) String() string {
	str := "IRCLib Connection\n"
	str += "----------------\n\n"
	if conn.Connected() {
		str += "Connected to " + conn.cfg.Server + "\n\n"
	} else {
		str += "Not currently connected!\n\n"
	}
	str += conn.Me().String() + "\n"
	if conn.st != nil {
		str += conn.st.String() + "\n"
	}
	return str
}
