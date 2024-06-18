package msg

import (
	"bytes"
	"context"
	"testing"

	"github.com/secure-conversation/elliptic"
	"github.com/secure-conversation/ident"
	"github.com/secure-conversation/sym"
)

func TestNewConversation(t *testing.T) {

	c, err := elliptic.NewCurve(elliptic.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	senderIdentityKey, err := c.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	recipientIdentityKey, err := c.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	recipientPubInfo := &PublicKeyInfo{
		PrivateKeyID: recipientIdentityKey.ID(),
		PublicKey:    recipientIdentityKey.PublicKey(),
	}

	content := []byte("Hello World")

	msg, key, err := NewConversation(senderIdentityKey, recipientPubInfo, content)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := msg.Verify(senderIdentityKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("unexpected signing failure")
	}

	if !ident.EqualValueID[elliptic.PrivateKeyID](msg.Data.metadata.recipientKeyID, recipientIdentityKey.ID()) {
		t.Fatal("unexpected id mismatch")
	}

	received, err := sym.Decrypt(msg.Data.content.ToMessage(), key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(received, content) {
		t.Fatal("content not decrypted correctly")
	}
}

func TestNewConversation_1(t *testing.T) {

	c, err := elliptic.NewCurve(elliptic.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	senderIdentityKey, err := c.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	recipientIdentityKey, err := c.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	recipientPubInfo := &PublicKeyInfo{
		PrivateKeyID: recipientIdentityKey.ID(),
		PublicKey:    recipientIdentityKey.PublicKey(),
	}

	content := []byte("Hello World")

	msg, key, err := NewConversation(senderIdentityKey, recipientPubInfo, content)
	if err != nil {
		t.Fatal(err)
	}

	b, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := elliptic.ParseSigned[*Message](b)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := msg2.Verify(senderIdentityKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("unexpected signing failure")
	}

	if !ident.EqualValueID[elliptic.PrivateKeyID](msg2.Data.metadata.recipientKeyID, recipientIdentityKey.ID()) {
		t.Fatal("unexpected id mismatch")
	}

	received, err := sym.Decrypt(msg2.Data.content.ToMessage(), key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(received, content) {
		t.Fatal("content not decrypted correctly")
	}
}

type testRecipient struct {
	stop             bool
	received_content []byte
	s                elliptic.PrivateKeyID
	c                map[ConversationID][]byte
	p                map[elliptic.PrivateKeyID]*elliptic.PrivateKey
}

func (t *testRecipient) GetKey(ctx context.Context, conID ConversationID) (key []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = nil
		}
	}()
	key = t.c[conID]
	return
}
func (t *testRecipient) SetKey(ctx context.Context, conID ConversationID, key []byte) error {
	t.c[conID] = key
	return nil
}
func (t *testRecipient) GetPrivateKey(ctx context.Context, keyID elliptic.PrivateKeyID) (key *elliptic.PrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = nil
		}
	}()
	key = t.p[keyID]
	return
}
func (t *testRecipient) GetSigningKey(ctx context.Context) *elliptic.PrivateKey {
	return t.p[t.s]
}
func (t *testRecipient) Handle(ctx context.Context, data []byte) (bool, []byte) {
	if t.stop {
		t.received_content = data
		return false, nil
	}
	return true, data
}

func TestMessage_Reply(t *testing.T) {

	var sender *testRecipient
	var recipient *testRecipient

	var recipientPubInfo *PublicKeyInfo

	content := []byte("Hello World")

	// Create recipient
	{
		r := &testRecipient{
			c: map[ConversationID][]byte{},
			p: map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		}

		c, err := elliptic.NewCurve(elliptic.CurveP256)
		if err != nil {
			t.Fatal(err)
		}

		recipientIdentityKey, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		r.p[recipientIdentityKey.ID()] = recipientIdentityKey
		r.s = recipientIdentityKey.ID()

		recipientPubInfo = &PublicKeyInfo{
			PrivateKeyID: recipientIdentityKey.ID(),
			PublicKey:    recipientIdentityKey.PublicKey(),
		}

		recipient = r
	}

	// Create sender
	{
		s := &testRecipient{
			stop: true, // This stops the conversation, stores reply from recipient
			c:    map[ConversationID][]byte{},
			p:    map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		}

		c, err := elliptic.NewCurve(elliptic.CurveP521)
		if err != nil {
			t.Fatal(err)
		}

		senderIdentityKey, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		s.p[senderIdentityKey.ID()] = senderIdentityKey
		s.s = senderIdentityKey.ID()

		sender = s
	}

	// Sender creates message, receiving one-time key for conversation
	var b []byte
	{
		var msg *elliptic.Signed[*Message]
		msg, key, err := NewConversation(sender.GetSigningKey(context.Background()), recipientPubInfo, content)
		if err != nil {
			t.Fatal(err)
		}
		// Sender stores one-time key for the conversation
		// so that they can unpack any replies they receive
		sender.SetKey(context.Background(), msg.Data.ConversationID(), key)

		// Serialise to mimic transport of message
		b, err = msg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Recipient agrees to conversation, processes message and sends back a reply
	{
		// Unpacks message, confirms from holder of private key and message intact
		receivedMessage, err := elliptic.ParseSigned[*Message](b)
		if err != nil {
			t.Fatal(err)
		}

		// Attempts to create reply
		reply, err := receivedMessage.Data.Reply(context.Background(), recipient)
		if err != nil {
			t.Fatal(err)
		}

		// Serialise to minic transport of message
		b, err = reply.Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Sender receives reply, unpacks, confirms from holder of private key ...
	receivedMessage, err := elliptic.ParseSigned[*Message](b)
	if err != nil {
		t.Fatal(err)
	}

	// Sender processes reply, which should be stopping the conversation
	reply, err := receivedMessage.Data.Reply(context.Background(), sender)
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil {
		t.Fatal("unexpected continance of messages")
	}

	// Should have received back the original message
	if !bytes.Equal(content, sender.received_content) {
		t.Fatal("unexpected mismatch in content")
	}
}
