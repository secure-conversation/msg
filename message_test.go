package msg

import (
	"bytes"
	"context"
	"fmt"
	"strings"
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
	handler Handler
	s       elliptic.PrivateKeyID
	c       map[ConversationID]*ConversationDetails
	p       map[elliptic.PrivateKeyID]*elliptic.PrivateKey
	p1      map[elliptic.PrivateKeyID]*elliptic.PublicKey
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
	return t.handler.Handle(ctx, data)
}

type storeHandler struct {
	received_content []byte
}

func (s *storeHandler) Handle(ctx context.Context, data []byte) (bool, []byte) {
	s.received_content = data
	return false, nil
}

type reflectHandler struct {
}

func (r *reflectHandler) Handle(ctx context.Context, data []byte) (bool, []byte) {
	return true, data
}

func TestMessage_Reply(t *testing.T) {

	sh := &storeHandler{}

	var sender = &testRecipient{
		handler: sh,
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      map[elliptic.PrivateKeyID]*elliptic.PublicKey{},
	}
	var recipient = &testRecipient{
		handler: &reflectHandler{},
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      map[elliptic.PrivateKeyID]*elliptic.PublicKey{},
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
	if !bytes.Equal(content, sh.received_content) {
		t.Fatal("unexpected mismatch in content")
	}
}

type decrementStoreHandler struct {
	startCounter     int
	counter          int
	prefix           string
	received_content []byte
}

func (d *decrementStoreHandler) Handle(ctx context.Context, data []byte) (bool, []byte) {
	d.counter--
	if d.counter > 0 {
		return true, fmt.Appendf([]byte{}, "%s %s", d.prefix, data)
	}
	d.received_content = data
	return false, nil
}

func TestMessage_Reply_1(t *testing.T) {

	// This test will use this handler to  prepend the prefix to the messages
	// being sent by the sender to the recipient, stopping once startCounter
	// messages have been transferred.  The recipient simply reflects what it
	// gets, so the message just grows with the prefix each time.
	//
	// After all transfers have completed, verify we get what we expected
	//
	// This demonstrates the send/reply loop and ability to stop.
	sh := &decrementStoreHandler{
		startCounter: 1000,
		prefix:       "Hello",
	}
	sh.counter = sh.startCounter // Decrement from that value

	var pubKeyMap = map[elliptic.PrivateKeyID]*elliptic.PublicKey{}

	var sender = &testRecipient{
		handler: sh,
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      pubKeyMap,
	}
	var recipient = &testRecipient{
		handler: &reflectHandler{},
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      pubKeyMap,
	}

	createRecipient := func(tr *testRecipient, m map[elliptic.PrivateKeyID]*elliptic.PublicKey) *PublicKeyInfo {
		c, err := elliptic.NewCurve(elliptic.CurveP256)
		if err != nil {
			t.Fatal(err)
		}

		recipientIdentityKey, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		tr.p[recipientIdentityKey.ID()] = recipientIdentityKey
		tr.s = recipientIdentityKey.ID()

		recipientPubInfo := &PublicKeyInfo{
			PrivateKeyID: recipientIdentityKey.ID(),
			PublicKey:    recipientIdentityKey.PublicKey(),
		}

		m[recipientIdentityKey.ID()] = recipientIdentityKey.PublicKey()

		return recipientPubInfo
	}

	// Create remote recipient, and hold onto their pubInfo
	var recipientPubInfo = createRecipient(recipient, pubKeyMap)

	// Create local sender
	createRecipient(sender, pubKeyMap)

	// Sender initiates the conversation
	var b []byte
	{
		ctx := context.Background()

		signingKey, err := sender.GetPrivateKey(ctx, sender.s)
		if err != nil {
			t.Fatal(err)
		}

		var details *ConversationDetails
		b, details, err = NewConversation(signingKey, recipientPubInfo, []byte("Hello World"))
		if err != nil {
			t.Fatal(err)
		}
		// Sender stores one-time key for the conversation
		// so that they can unpack any replies they receive
		sender.SetDetails(context.Background(), details)
	}

	// Recipient agrees to conversation, processes message and sends back a reply
	reply, err := HandleConversationMessage(context.Background(), b, recipient)
	if err != nil {
		t.Fatal(err)
	}

	// Loop until message cycle is completed (via decrementStoreHandler.counter decrementing to zero)
	// Flip the Recipient as messages pass between sender and recipient, mimicking message transfers
	var r = sender
	for len(reply) > 0 {
		reply, err = HandleConversationMessage(context.Background(), reply, r)
		if err != nil {
			t.Fatal(err)
		}
		if r == sender {
			r = recipient
		} else {
			r = sender
		}
	}

	// Should have received back the original message with lots of Hellos
	parts := strings.Split(string(sh.received_content), " ")
	countHellos := 0
	for _, part := range parts {
		if part == sh.prefix {
			countHellos++
		}
	}
	if countHellos != sh.startCounter {
		t.Fatalf("unexpected mismatch in transfers.  Expected %d '%s' prefixes, but got %d", sh.startCounter, sh.prefix, countHellos)
	}
}

func ExampleNewConversation() {

	// This test will use this handler to  prepend the prefix to the messages
	// being sent by the sender to the recipient, stopping once startCounter
	// messages have been transferred.  The recipient simply reflects what it
	// gets, so the message just grows with the prefix each time.
	//
	// After all transfers have completed, verify we get what we expected
	//
	// This demonstrates the send/reply loop and ability to stop.
	sh := &decrementStoreHandler{
		startCounter: 100,
		prefix:       "Hello",
	}
	sh.counter = sh.startCounter // Decrement from that value

	var pubKeyMap = map[elliptic.PrivateKeyID]*elliptic.PublicKey{}

	var sender = &testRecipient{
		handler: sh,
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      pubKeyMap,
	}
	var recipient = &testRecipient{
		handler: &reflectHandler{},
		c:       map[ConversationID]*ConversationDetails{},
		p:       map[elliptic.PrivateKeyID]*elliptic.PrivateKey{},
		p1:      pubKeyMap,
	}

	createRecipient := func(tr *testRecipient, m map[elliptic.PrivateKeyID]*elliptic.PublicKey, ct elliptic.CurveType) *PublicKeyInfo {
		c, _ := elliptic.NewCurve(ct)

		recipientIdentityKey, _ := c.GenerateKey()

		tr.p[recipientIdentityKey.ID()] = recipientIdentityKey
		tr.s = recipientIdentityKey.ID()

		recipientPubInfo := &PublicKeyInfo{
			PrivateKeyID: recipientIdentityKey.ID(),
			PublicKey:    recipientIdentityKey.PublicKey(),
		}

		m[recipientIdentityKey.ID()] = recipientIdentityKey.PublicKey()

		return recipientPubInfo
	}

	// Create remote recipient, and hold onto their pubInfo
	var recipientPubInfo = createRecipient(recipient, pubKeyMap, elliptic.CurveP256)

	// Create local sender
	createRecipient(sender, pubKeyMap, elliptic.CurveP521)

	// Sender initiates the conversation
	var b []byte
	{
		ctx := context.Background()

		signingKey, _ := sender.GetPrivateKey(ctx, sender.s)

		var details *ConversationDetails
		b, details, _ = NewConversation(signingKey, recipientPubInfo, []byte("Hello World"))

		// Sender stores one-time key for the conversation
		// so that they can unpack any replies they receive
		sender.SetDetails(context.Background(), details)
	}

	// Recipient agrees to conversation, processes message and sends back a reply
	reply, _ := HandleConversationMessage(context.Background(), b, recipient)

	// Loop until message cycle is completed (via decrementStoreHandler.counter decrementing to zero)
	// Flip the Recipient as messages pass between sender and recipient, mimicking message transfers
	var r = sender
	for len(reply) > 0 {
		reply, _ = HandleConversationMessage(context.Background(), reply, r)

		if r == sender {
			r = recipient
		} else {
			r = sender
		}
	}

	// Should have received back the original message with lots of Hellos
	parts := strings.Split(string(sh.received_content), " ")
	countHellos := 0
	for _, part := range parts {
		if part == sh.prefix {
			countHellos++
		}
	}

	fmt.Println(countHellos)
	// Output: 100
}
