package msg

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/secure-conversation/elliptic"
	"github.com/secure-conversation/ident"
	"github.com/secure-conversation/sym"
)

// Metadata describes the conversation itself.
// If the ConversationID is new, then the RecipientKeyID and OneTimePubKey must be provided,
// so that the shared secret (the encryption key for the Content) can be determined.
// Once a conversation is started, only the ConversationID should be provided in the metadata.
type Metadata struct {
	// conversationID is the unique identifier of this conversation
	conversationID ConversationID
	// recipientKeyID is the unique identifier of the private key owned by the recipient, whose public key has been selected by the conversation initiator
	recipientKeyID elliptic.PrivateKeyID
	// oneTimePubKey is the public key that the conversation initiator has created from a one-time private key created for this conversation
	oneTimePubKey *elliptic.PublicKey
}

// Collect ensures that the signature is created from consistent inputs
func (m *Metadata) Collect() []byte {
	h := sha256.New()
	h.Write(m.conversationID[:])
	h.Write(elliptic.SigningMaterialSpacer())
	h.Write(m.recipientKeyID[:])
	h.Write(elliptic.SigningMaterialSpacer())
	if m.oneTimePubKey != nil {
		b, _ := m.oneTimePubKey.Marshal()
		h.Write(b)
	}
	h.Write(elliptic.SigningMaterialSpacer())
	return h.Sum(nil)
}

// Message is a single transfer of information between the parties involved in the conversation.
// Sufficient information is provided such that the correct parties can decrypt the Content.
type Message struct {
	// metadata describes the conversation itself
	metadata *Metadata
	// content contains the information being transferred
	content *EncryptedContent
}

// ConversationID returns the identifier of the conversation that this message is part of
func (m *Message) ConversationID() ConversationID {
	return ident.CopyID(m.metadata.conversationID)
}

// ErrMissingHandler returned when Message.Reply is called with a nil Handler
var ErrMissingHandler = errors.New("handler must be provided")

// ErrInvalidMessage returned if a message is replayed
var ErrInvalidMessage = errors.New("metadata reprovided for existing conversation")

// ErrMissingMessageMetadata returned when a new conversation has insufficient metadat
var ErrMissingMessageMetadata = errors.New("metadata missing for new conversation")

// handle allows a Recipient to generate a response Message if desired.
func (m *Message) handle(ctx context.Context, key []byte, h Handler) (*Message, error) {

	if h == nil {
		return nil, ErrMissingHandler
	}

	// Decrypt the message, which should have been encrypted with the key
	msg, err := sym.Decrypt(m.content.ToMessage(), key)
	if err != nil {
		return nil, err
	}

	// Recipient now processes the decrypted information
	shouldReply, b := h.Handle(ctx, msg)
	if !shouldReply {
		return nil, nil
	}

	// Use the same key to encrypt the response
	e, err := NewEncryptedContent(b, key)
	if err != nil {
		return nil, err
	}

	// Recipient only needs the conversationID - will have the other metadata
	return &Message{
		metadata: &Metadata{
			conversationID: m.metadata.conversationID,
		},
		content: e,
	}, nil
}

// Collect ensures that the signature is created from consistent inputs
func (m *Message) Collect() []byte {
	h := sha256.New()
	h.Write(m.metadata.Collect())
	h.Write(elliptic.SigningMaterialSpacer())
	if m.content != nil {
		h.Write(m.content.Collect())
	}
	h.Write(elliptic.SigningMaterialSpacer())
	return h.Sum(nil)
}

// Marshal encodes this instance to JSON
func (m *Message) Marshal() ([]byte, error) {
	jm := &msg{
		Metadata: &msgM{
			ConversationID: base64.RawStdEncoding.EncodeToString(m.metadata.conversationID[:]),
			RecipientKeyID: base64.RawStdEncoding.EncodeToString(m.metadata.recipientKeyID[:]),
		},
		Content: &msgC{
			Algo:       m.content.Algo.String(),
			Ciphertext: base64.RawStdEncoding.EncodeToString(m.content.Ciphertext),
			Nonce:      base64.RawStdEncoding.EncodeToString(m.content.Nonce),
		},
	}

	if m.metadata.oneTimePubKey != nil {
		b, err := m.metadata.oneTimePubKey.Marshal()
		if err != nil {
			return nil, err
		}
		jm.Metadata.OneTimePubKey = string(b)
	}

	return json.Marshal(jm)
}

type msgM struct {
	ConversationID string `json:"c"`
	RecipientKeyID string `json:"r"`
	OneTimePubKey  string `json:"k"`
}

type msgC struct {
	Algo       string `json:"a"`
	Ciphertext string `json:"c"`
	Nonce      string `json:"n"`
}

type msg struct {
	Metadata *msgM `json:"m"`
	Content  *msgC `json:"c"`
}

// UnMarshal populates this instance from the JSON encoded data provided
func (m *Message) UnMarshal(data []byte) error {
	var jm msg
	err := json.Unmarshal(data, &jm)
	if err != nil {
		return err
	}

	con, err := base64.RawStdEncoding.DecodeString(jm.Metadata.ConversationID)
	if err != nil {
		return err
	}
	recipientID, err := base64.RawStdEncoding.DecodeString(jm.Metadata.RecipientKeyID)
	if err != nil {
		return err
	}
	var pubKey *elliptic.PublicKey
	if len(jm.Metadata.OneTimePubKey) != 0 {
		pubKey, err = elliptic.UnMarshalPublicKey([]byte(jm.Metadata.OneTimePubKey))
		if err != nil {
			return err
		}
	}

	a, err := sym.ParseAlgo(jm.Content.Algo)
	if err != nil {
		return err
	}
	cipher, err := base64.RawStdEncoding.DecodeString(jm.Content.Ciphertext)
	if err != nil {
		return err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(jm.Content.Nonce)
	if err != nil {
		return err
	}

	m.metadata = &Metadata{
		oneTimePubKey: pubKey,
	}
	copy(m.metadata.conversationID[:], con)
	copy(m.metadata.recipientKeyID[:], recipientID)

	m.content = &EncryptedContent{
		Algo:       a,
		Ciphertext: cipher,
		Nonce:      nonce,
	}

	return nil
}

// New returns a new empty instance of Message
func (m *Message) New() any {
	return &Message{}
}

// ConversationDetails holds the details needed to participate in the conversation
type ConversationDetails struct {
	// ConversationID is the unique identifier of a conversation
	ConversationID ConversationID
	// SenderKeyID is the PrivateKeyID of the message sender of the conversation - all messages to recipient must be
	// signed with this key to confirm the same originator
	SenderKeyID elliptic.PrivateKeyID
	// RecipientKeyID is the PrivateKeyID that the initiator selected of those available for the recipient - all messages from the
	// recipient must be signed with this key to confirm the seam originator
	RecipientKeyID elliptic.PrivateKeyID
	// SharedSecret is the secret created for this conversation
	SharedSecret []byte
}

// NewConversation creates the Signed[Message] that can initiate a conversation with the recipient,
// returning ConversationDetails so that the messages can be correctly created and verified
func NewConversation(signerPriKey *elliptic.PrivateKey, recipientInfo *PublicKeyInfo, content []byte) ([]byte, *ConversationDetails, error) {
	return NewConversationWithAlgo(signerPriKey, recipientInfo, content, sym.AESGCM)
}

// NewConversationWithAlgo creates the Signed[Message] that can initiate a conversation with the recipient,
// identified by their public key info, using the symmetric encryption algorithm as specified by the caller,
// and returning ConversationDetails so that the messages can be correctly created and verified
func NewConversationWithAlgo(signerPriKey *elliptic.PrivateKey, recipientInfo *PublicKeyInfo, content []byte, algo sym.Algo) ([]byte, *ConversationDetails, error) {

	// Use ECDH to create a shared secret for this conversation with one-time keys
	oneTimePrivKey, key, err := elliptic.NewSharedSecret(recipientInfo.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the content of the message
	msg, err := NewEncryptedContentWithAlgo(content, key, algo)
	if err != nil {
		return nil, nil, err
	}

	// Initial message contains full metadata, so recipient can decode
	m := &Message{
		metadata: &Metadata{
			conversationID: ident.NewID[ConversationID](),
			recipientKeyID: recipientInfo.PrivateKeyID,
			oneTimePubKey:  oneTimePrivKey.PublicKey(),
		},
		content: msg,
	}

	// Sign to prove it is from the holder of the signerPriKey,
	// and to demonstrate message contents have not been tampered in transit.
	s, err := elliptic.NewSigned(signerPriKey, m)
	if err != nil {
		return nil, nil, err
	}

	// Serialise ready for transfer
	b, err := s.Marshal()
	if err != nil {
		return nil, nil, err
	}

	// Note from the initiator's perspective, any sender will be for messages received,
	// and this party will act as a recipient
	return b, &ConversationDetails{
		ConversationID: ident.CopyID(m.metadata.conversationID),
		RecipientKeyID: ident.CopyID(signerPriKey.ID()),
		SharedSecret:   key,
		SenderKeyID:    ident.CopyID(recipientInfo.PrivateKeyID),
	}, nil
}

// ErrSignatureIDMismatch returned if an incorrect PrivateKeyID was used for signing a conversation message
var ErrSignatureIDMismatch = errors.New("unexpected signing PrivateKeyID")

// ErrSignatureInvalid returned if the signature could not be verified
var ErrSignatureInvalid = errors.New("invalid signature")

// ErrMissingPubKey returned if the Recipient does not have access to the sender's public key
var ErrMissingPubKey = errors.New("missing sender public key")

// ErrMissingPrivateKey returned if the Recipient does has lost access to their private key
var ErrMissingPrivateKey = errors.New("missing receiver private key")

// HandleConversationMessage deserialises and processes a Signed[Message] based on the Recipient,
// returning a serialised Signed[Message] if one is to be returned
func HandleConversationMessage(ctx context.Context, data []byte, r Recipient) ([]byte, error) {

	s, err := elliptic.ParseSigned[*Message](data)
	if err != nil {
		return nil, err
	}

	// Will already have details if the conversation is not new
	details, err := r.GetDetails(ctx, s.Data.ConversationID())
	if err != nil {
		return nil, err
	}

	if details != nil {
		// Verify that the message is ok - seeing more metadata than expected is indicative of a replay
		if !ident.EmptyID(s.Data.metadata.recipientKeyID) || s.Data.metadata.oneTimePubKey != nil {
			return nil, ErrInvalidMessage
		}

		// Messages must always be consistently signed within each conversation
		if !ident.EqualValueID(details.SenderKeyID, s.ID) {
			return nil, ErrSignatureIDMismatch
		}
	} else {
		// Conversation is new, create and store new details
		if ident.EmptyID(s.Data.metadata.recipientKeyID) || s.Data.metadata.oneTimePubKey == nil {
			return nil, ErrMissingMessageMetadata
		}

		privKey, err := r.GetPrivateKey(ctx, s.Data.metadata.recipientKeyID)
		if err != nil {
			return nil, err
		}
		if privKey == nil {
			// Odd scenario but possible
			return nil, ErrMissingPrivateKey
		}

		key, err := elliptic.RecreateSharedSecret(privKey, s.Data.metadata.oneTimePubKey)
		if err != nil {
			return nil, err
		}

		details = &ConversationDetails{
			ConversationID: s.Data.metadata.conversationID,
			SenderKeyID:    s.ID,
			RecipientKeyID: s.Data.metadata.recipientKeyID,
			SharedSecret:   key,
		}

		err = r.SetDetails(ctx, details)
		if err != nil {
			return nil, err
		}
	}

	// This should be generally available - do not continue
	// if the message cannot be authenticated
	pubKey, err := r.GetPublicKey(ctx, details.SenderKeyID)
	if err != nil {
		return nil, err
	}
	if pubKey == nil {
		return nil, ErrMissingPubKey
	}
	ok, err := s.Verify(pubKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrSignatureInvalid
	}

	// Message has been authenticated as from the original sender initiating the
	// conversation, and the message is untampered, so process it
	response, err := s.Data.handle(ctx, details.SharedSecret, r)
	if err != nil {
		return nil, err
	}
	if response == nil {
		// Handler decided no reply was required
		return nil, nil
	}

	// This is one of the Recipient's own keys, so should be available
	privKey, err := r.GetPrivateKey(ctx, details.RecipientKeyID)
	if err != nil {
		return nil, err
	}
	if privKey == nil {
		// Odd scenario but possible
		return nil, ErrMissingPrivateKey
	}

	// Sign and serialise
	reply, err := elliptic.NewSigned(privKey, response)
	if err != nil {
		return nil, err
	}
	b, err := reply.Marshal()
	if err != nil {
		return nil, err
	}

	return b, nil
}
