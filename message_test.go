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

	b, details, err := NewConversation(senderIdentityKey, recipientPubInfo, content)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := elliptic.ParseSigned[*Message](b)
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

	received, err := sym.Decrypt(msg.Data.content.ToMessage(), details.SharedSecret)
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

	b, details, err := NewConversation(senderIdentityKey, recipientPubInfo, content)
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

	received, err := sym.Decrypt(msg2.Data.content.ToMessage(), details.SharedSecret)
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
	c                map[ConversationID]*ConversationDetails
	p                map[elliptic.PrivateKeyID]*elliptic.PrivateKey
	p1               map[elliptic.PrivateKeyID]*elliptic.PublicKey
}

func (t *testRecipient) GetDetails(ctx context.Context, conID ConversationID) (details *ConversationDetails, err error) {
	defer func() {
		if r := recover(); r != nil {
			details = nil
			err = nil
		}
	}()
	details = t.c[conID]
	return
}
func (t *testRecipient) SetDetails(ctx context.Context, details *ConversationDetails) error {
	t.c[details.ConversationID] = details
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
func (t *testRecipient) GetPublicKey(ctx context.Context, keyID elliptic.PrivateKeyID) (key *elliptic.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = nil
		}
	}()
	key = t.p1[keyID]
	return
}
func (t *testRecipient) Handle(ctx context.Context, data []byte) (bool, []byte) {
	if t.stop {
		t.received_content = data
		return false, nil
	}
	return true, data
}

func TestMessage_Reply(t *testing.T) {

	var sender = &testRecipient{
		stop: true, // This stops the conversation, stores reply from recipient
		c:    map[ConversationID]*ConversationDetails{},
		p:    map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:   map[elliptic.PrivateKeyID]*elliptic.PublicKey{},
	}
	var recipient = &testRecipient{
		c:  map[ConversationID]*ConversationDetails{},
		p:  map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1: map[elliptic.PrivateKeyID]*elliptic.PublicKey{},
	}

	var recipientPubInfo *PublicKeyInfo

	content := []byte("Hello World")

	// Create recipient keys
	{
		c, err := elliptic.NewCurve(elliptic.CurveP256)
		if err != nil {
			t.Fatal(err)
		}

		recipientIdentityKey, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		recipient.p[recipientIdentityKey.ID()] = recipientIdentityKey
		recipient.s = recipientIdentityKey.ID()

		recipientPubInfo = &PublicKeyInfo{
			PrivateKeyID: recipientIdentityKey.ID(),
			PublicKey:    recipientIdentityKey.PublicKey(),
		}

		sender.p1[recipientIdentityKey.ID()] = recipientIdentityKey.PublicKey()
	}

	// Create sender keys
	{
		c, err := elliptic.NewCurve(elliptic.CurveP521)
		if err != nil {
			t.Fatal(err)
		}

		senderIdentityKey, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		sender.p[senderIdentityKey.ID()] = senderIdentityKey
		sender.s = senderIdentityKey.ID()

		recipient.p1[senderIdentityKey.ID()] = senderIdentityKey.PublicKey()
	}

	// Sender creates message, receiving one-time key for conversation
	var b []byte
	{
		ctx := context.Background()

		signingKey, err := sender.GetPrivateKey(ctx, sender.s)
		if err != nil {
			t.Fatal(err)
		}

		msg, details, err := NewConversation(signingKey, recipientPubInfo, content)
		if err != nil {
			t.Fatal(err)
		}
		// Sender stores one-time key for the conversation
		// so that they can unpack any replies they receive
		sender.SetDetails(context.Background(), details)

		// Mimic transportation
		b = msg
	}

	// Recipient agrees to conversation, processes message and sends back a reply
	{
		reply, err := HandleConversationMessage(context.Background(), b, recipient)
		if err != nil {
			t.Fatal(err)
		}

		// Mimic transportation
		b = reply
	}

	// Sender receives reply, should be no further messages
	reply, err := HandleConversationMessage(context.Background(), b, sender)
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
