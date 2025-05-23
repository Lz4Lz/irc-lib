package client

// this file contains the basic set of event handlers
// to manage tracking an irc connection etc.

import (
	"sort"
	"strings"
	"sync"
	"time"

	"encoding/base64"

	"github.com/lz4lz/irc-lib/logging"
)

// saslCap is the IRCv3 capability used for SASL authentication.
const saslCap = "sasl"

// sets up the internal event handlers to do essential IRC protocol things
var internalHandlers = map[string]HandlerFunc{
	REGISTER:     (*Connection).h_REGISTER,
	"001":        (*Connection).h_001, // RPL_WELCOME: Welcome message
	"433":        (*Connection).h_433, // ERR_NICKNAMEINUSE: Chosen nick is occupied
	CTCP:         (*Connection).h_CTCP,
	NICK:         (*Connection).h_NICK,
	PING:         (*Connection).h_PING,
	CAP:          (*Connection).h_CAP,
	"410":        (*Connection).h_410, // ERR_INVALIDCAPCMD: Invalid cap command
	AUTHENTICATE: (*Connection).h_AUTHENTICATE,
	"903":        (*Connection).h_903, // RPL_SASLSUCCESS: SASL authentication successful
	"904":        (*Connection).h_904, // ERR_SASLFAIL: SASL authentication failed
	"908":        (*Connection).h_908, // RPL_SASLMECHS: Supported SASL mechanisms
}

// most irc numerics are documented here: https://modern.ircdocs.horse/#numerics
// a better list of possible lines can be found here: https://ircv3.net/registry

// set up the ircv3 capabilities supported by this client which will be requested by default to the server.
var defaultCaps = []string{}

func (conn *Connection) addIntHandlers() {
	for n, h := range internalHandlers {
		// internal handlers are essential for the IRC client
		// to function, so we don't save their Removers here
		conn.handle(n, h)
	}
}

// Basic ping/pong handler
func (conn *Connection) h_PING(line *Line) {
	conn.Pong(line.Args[0])
}

// Handler for initial registration with server once tcp connection is made.
func (conn *Connection) h_REGISTER(line *Line) {
	if conn.cfg.EnableCapabilityNegotiation {
		conn.Cap(CAP_LS)
	}

	if conn.cfg.Pass != "" {
		conn.Pass(conn.cfg.Pass)
	}
	conn.Nick(conn.cfg.Me.Nick)
	conn.User(conn.cfg.Me.Ident, conn.cfg.Me.Name)
}

func (conn *Connection) getRequestCapabilities() *capSet {
	s := capabilitySet()

	// add capabilities supported by the client
	s.Add(defaultCaps...)

	if conn.cfg.Sasl != nil {
		// add the SASL cap if enabled
		s.Add(saslCap)
	}

	// add capabilities requested by the user
	s.Add(conn.cfg.Capabilities...)

	return s
}

func (conn *Connection) negotiateCapabilities(supportedCaps []string) {
	conn.supportedCaps.Add(supportedCaps...)

	reqCaps := conn.getRequestCapabilities()
	reqCaps.Intersect(conn.supportedCaps)

	if reqCaps.Size() > 0 {
		conn.Cap(CAP_REQ, reqCaps.Slice()...)
	} else {
		conn.Cap(CAP_END)
	}
}

func (conn *Connection) handleCapAck(caps []string) {
	gotSasl := false
	for _, cap := range caps {
		conn.currentCaps.Add(cap)

		if conn.cfg.Sasl != nil && cap == saslCap {
			mech, ir, err := conn.cfg.Sasl.Start()

			if err != nil {
				logging.Warn("SASL authentication failed: %v", err)
				continue
			}

			// TODO: when IRC 3.2 capability negotiation is supported, ensure the
			// capability value is used to match the chosen mechanism

			gotSasl = true
			conn.saslRemainingData = ir

			conn.Authenticate(mech)
		}
	}

	if !gotSasl {
		conn.Cap(CAP_END)
	}
}

func (conn *Connection) handleCapNak(caps []string) {
	conn.Cap(CAP_END)
}

const (
	CAP_LS  = "LS"
	CAP_REQ = "REQ"
	CAP_ACK = "ACK"
	CAP_NAK = "NAK"
	CAP_END = "END"
)

type capSet struct {
	caps map[string]bool
	mu   sync.RWMutex
}

func capabilitySet() *capSet {
	return &capSet{
		caps: make(map[string]bool),
	}
}

func (c *capSet) Add(caps ...string) {
	c.mu.Lock()
	for _, cap := range caps {
		if strings.HasPrefix(cap, "-") {
			c.caps[cap[1:]] = false
		} else {
			c.caps[cap] = true
		}
	}
	c.mu.Unlock()
}

func (c *capSet) Has(cap string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.caps[cap]
}

// Intersect computes the intersection of two sets.
func (c *capSet) Intersect(other *capSet) {
	c.mu.Lock()

	for cap := range c.caps {
		if !other.Has(cap) {
			delete(c.caps, cap)
		}
	}

	c.mu.Unlock()
}

func (c *capSet) Slice() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	capSlice := make([]string, 0, len(c.caps))
	for cap := range c.caps {
		capSlice = append(capSlice, cap)
	}

	// make output predictable for testing
	sort.Strings(capSlice)
	return capSlice
}

func (c *capSet) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.caps)
}

// This handler is triggered when an invalid cap command is received by the server.
func (conn *Connection) h_410(line *Line) {
	logging.Warn("Invalid cap subcommand: ", line.Args[1])
}

// Handler for capability negotiation commands.
// Note that even if multiple CAP_END commands may be sent to the server during negotiation,
// only the first will be considered.
func (conn *Connection) h_CAP(line *Line) {
	subcommand := line.Args[1]

	caps := strings.Fields(line.Text())
	switch subcommand {
	case CAP_LS:
		conn.negotiateCapabilities(caps)
	case CAP_ACK:
		conn.handleCapAck(caps)
	case CAP_NAK:
		conn.handleCapNak(caps)
	}
}

// Handler for SASL authentication
func (conn *Connection) h_AUTHENTICATE(line *Line) {
	if conn.cfg.Sasl == nil {
		return
	}

	if conn.saslRemainingData != nil {
		data := "+" // plus sign representing empty data
		if len(conn.saslRemainingData) > 0 {
			data = base64.StdEncoding.EncodeToString(conn.saslRemainingData)
		}

		// TODO: batch data into chunks of 400 bytes per the spec

		conn.Authenticate(data)
		conn.saslRemainingData = nil
		return
	}

	// TODO: handle data over 400 bytes long (which will be chunked into multiple messages per the spec)
	challenge, err := base64.StdEncoding.DecodeString(line.Args[0])
	if err != nil {
		logging.Error("Failed to decode SASL challenge: %v", err)
		return
	}

	response, err := conn.cfg.Sasl.Next(challenge)
	if err != nil {
		logging.Error("Failed to generate response for SASL challenge: %v", err)
		return
	}

	// TODO: batch data into chunks of 400 bytes per the spec
	data := base64.StdEncoding.EncodeToString(response)
	conn.Authenticate(data)
}

// Handler for RPL_SASLSUCCESS.
func (conn *Connection) h_903(line *Line) {
	conn.Cap(CAP_END)
}

// Handler for RPL_SASLFAILURE.
func (conn *Connection) h_904(line *Line) {
	logging.Warn("SASL authentication failed")
	conn.Cap(CAP_END)
}

// Handler for RPL_SASLMECHS.
func (conn *Connection) h_908(line *Line) {
	logging.Warn("SASL mechanism not supported, supported mechanisms are: %v", line.Args[1])
	conn.Cap(CAP_END)
}

// Handler to trigger a CONNECTED event on receipt of numeric 001
// :<server> 001 <nick> :Welcome message <nick>!<user>@<host>
func (conn *Connection) h_001(line *Line) {
	// We're connected! Defer this for control flow reasons.
	defer conn.dispatch(&Line{Cmd: CONNECTED, Time: time.Now()})

	// Accept the server's opinion of what our nick actually is
	// and record our ident and hostname (from the server's perspective)
	me, nick, t := conn.Me(), line.Target(), line.Text()
	if idx := strings.LastIndex(t, " "); idx != -1 {
		t = t[idx+1:]
	}
	_, ident, host, ok := parseUserHost(t)

	if me.Nick != nick {
		logging.Warn("Server changed our nick on connect: old=%q new=%q", me.Nick, nick)
	}
	if conn.st != nil {
		if ok {
			conn.st.NickInfo(me.Nick, ident, host, me.Name)
		}
		conn.cfg.Me = conn.st.ReNick(me.Nick, nick)
	} else {
		conn.cfg.Me.Nick = nick
		if ok {
			conn.cfg.Me.Ident = ident
			conn.cfg.Me.Host = host
		}
	}
}

// XXX: do we need 005 protocol support message parsing here?
// probably in the future, but I can't quite be arsed yet.
/*
	:irc.pl0rt.org 005 GoTest CMDS=KNOCK,MAP,DCCALLOW,USERIP UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=20 CHANLIMIT=#:20 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 :are supported by this server
	:irc.pl0rt.org 005 GoTest MAXTARGETS=20 WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMT NETWORK=bb101.net CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT :are supported by this server
	:irc.pl0rt.org 005 GoTest STATUSMSG=~&@%+ EXCEPTS INVEX :are supported by this server
*/

// Handler to deal with "433 :Nickname already in use"
func (conn *Connection) h_433(line *Line) {
	// Args[1] is the new nick we were attempting to acquire
	me := conn.Me()
	neu := conn.cfg.NewNick(line.Args[1])
	conn.Nick(neu)
	if !line.argslen(1) {
		return
	}
	// if this is happening before we're properly connected (i.e. the nick
	// we sent in the initial NICK command is in use) we will not receive
	// a NICK message to confirm our change of nick, so ReNick here...
	if line.Args[1] == me.Nick {
		if conn.st != nil {
			conn.cfg.Me = conn.st.ReNick(me.Nick, neu)
		} else {
			conn.cfg.Me.Nick = neu
		}
	}
}

// Handle VERSION requests and CTCP PING
func (conn *Connection) h_CTCP(line *Line) {
	if line.Args[0] == VERSION {
		conn.CtcpReply(line.Nick, VERSION, conn.cfg.Version)
	} else if line.Args[0] == PING && line.argslen(2) {
		conn.CtcpReply(line.Nick, PING, line.Args[2])
	}
}

// Handle updating our own NICK if we're not using the state tracker
func (conn *Connection) h_NICK(line *Line) {
	if conn.st == nil && line.Nick == conn.cfg.Me.Nick {
		conn.cfg.Me.Nick = line.Args[0]
	}
}
