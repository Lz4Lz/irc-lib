package util

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/lz4lz/irc-lib/client"
)

// generateLabel generates a unique label for message co-relation
func generateLabel() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()+int64(rand.Intn(1000)))
}

// Message represents a message
type Message struct {
	// The network-unique ID of the message.
	// This should be generated by the server if the 'message-ids' spec is available.
	// If the message originates from this clients, the ID has to be set later when
	// the server echoes the message back (if 'echo-message' is available).
	// Documentation: https://ircv3.net/specs/extensions/message-ids
	Id string

	// Temporary client-defined ID used to map messages.
	Label string

	// Sender is the sender origin of the message.
	Sender string

	// Target is the recipient of the message.
	Target string

	// Message text content.
	Text string

	// Indicates whether message has been deleted on server.
	// This is primarily used by the WIP message-redaction spec.
	// https://ircv3.net/specs/extensions/message-redaction.
	// This is part of the WIP 'Persistence' spec group.
	IsDeleted bool

	// If this is not nil, it points to the message being replied to.
	// This means that this message should be treated as a reply in styling scenarios.
	ReplyTo *Message
}

// NewMessage returns a new message with the specified target and text content.
// Some fields are only populated upon sending it with MessageStore.SendMessage.
func NewMessage(target, text string) *Message {
	return &Message{
		Id:        "",
		Label:     "l" + generateLabel(),
		Sender:    "",
		Target:    target,
		Text:      text,
		IsDeleted: false,
		ReplyTo:   nil, // TODO: Implement replies
	}
}

// MessageStore stores and manages messages
type MessageStore struct {
	messages map[string]*Message
	mu       sync.Mutex
	out      chan *Message
}

// Add or update a message in the store.
// This can be used for manual overrides but it is not recommended.
func (ms *MessageStore) AddOrUpdateLocal(msg *Message) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.messages[msg.Label] = msg
}

// SendMessage sends a message over the connection.
// Make sure msg.Label is client-unique.
func (ms *MessageStore) SendMessage(conn *client.Connection, msg *Message) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	labelsSupported := conn.SupportsCapability("labeled-response")

	for _, s := range client.SplitMessage(msg.Text, conn.Config().SplitLen) {
		var line string
		if labelsSupported {
			line = fmt.Sprintf("@label=%s PRIVMSG %s :%s", msg.Label, msg.Target, s)
		} else {
			line = fmt.Sprintf("PRIVMSG %s :%s", msg.Target, s)
		}
		conn.Raw(line)
	}

	msg.Sender = conn.StateTracker().Me().Nick

	ms.messages[msg.Label] = msg
	ms.out <- msg
}

// SendNewMessage sends a message just like SendMessage, but it creates
// the message from given parameters instead of sending an existing message.
func (ms *MessageStore) SendNewMessage(conn *client.Connection, target, text string) {
	msg := NewMessage(target, text)
	ms.SendMessage(conn, msg)
}

// FuncHandler implements an IRCLib FuncHandler for PRIVMSGs
func (ms *MessageStore) FuncHandler(conn *client.Connection, line *client.Line) {
	if line.Cmd != client.PRIVMSG || line.Tags == nil {
		return
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Handle our own messages (local)
	if line.Nick == conn.Me().Nick && ms.messages[line.Tags["label"]] != nil {
		if line.Tags["msgid"] != "" {
			ms.messages[line.Tags["label"]].Id = line.Tags["msgid"]
		}

		return
	}

	// Handle others (remote)
	msg := ms.messages["r"+line.Tags["msgid"]]
	if msg == nil {
		msg = &Message{
			Id:        line.Tags["msgid"],
			Label:     "r" + line.Tags["msgid"],
			Sender:    line.Nick,
			Target:    line.Target(),
			Text:      line.Text(),
			IsDeleted: false,
			ReplyTo:   nil,
		}
		ms.messages[msg.Label] = msg
		ms.out <- msg
		return
	}
}
