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

// ConversationManagerKey manages the keys for conversations
type ConversationKeyManager interface {
	// GetConversationKey returns the shared encryption key for the conversation
	GetKey(context.Context, ConversationID) ([]byte, error)
	// SetConversationKey allows the shared encryption key to be stored against the conversation by the recipient
	SetKey(context.Context, ConversationID, []byte) error
}

// PrivateKeyManager manages private keys
type PrivateKeyManager interface {
	// GetPrivateKey retrieves the recipient's private key based on the PrivateKeyID
	GetPrivateKey(context.Context, elliptic.PrivateKeyID) (*elliptic.PrivateKey, error)
	// GetSigningKey returns the PrivateKey to be used to sign responses
	GetSigningKey(ctx context.Context) *elliptic.PrivateKey
}

// Recipient specifies the functions needed to respond to a received Message
type Recipient interface {
	ConversationKeyManager
	PrivateKeyManager
	// Handle is called to allow the Recipient to
	Handle(ctx context.Context, data []byte) (bool, []byte)
}

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

var ErrMissingRecipient = errors.New("recipient must be provided")
var ErrInvalidMessage = errors.New("metadata reprovided for existing conversation")
var ErrMissingMessageMetadata = errors.New("metadata missing for new conversation")

// Reply allows a Recipient to generate a response Message if desired.
func (m *Message) Reply(ctx context.Context, r Recipient) (*elliptic.Signed[*Message], error) {

	if r == nil {
		return nil, ErrMissingRecipient
	}

	// Attempt to retrieve the shared key, which should exist if the conversation has started
	key, err := r.GetKey(ctx, m.metadata.conversationID)
	if err != nil {
		return nil, err
	}

	if key != nil {
		// Verify that the message is ok - seeing more metadata than expected is indicative of a replay
		if !ident.EmptyID(m.metadata.recipientKeyID) || m.metadata.oneTimePubKey != nil {
			return nil, ErrInvalidMessage
		}
	} else {
		// Conversation is new, so metadata must be completely provided
		if ident.EmptyID(m.metadata.recipientKeyID) || m.metadata.oneTimePubKey == nil {
			return nil, ErrMissingMessageMetadata
		}

		// Metadata must point to a known private key belonging to the recipient
		privKey, err := r.GetPrivateKey(ctx, m.metadata.recipientKeyID)
		if err != nil {
			return nil, err
		}

		// Recipient should be able to regenerate the key, using ECDH
		key, err = elliptic.RecreateSharedSecret(privKey, m.metadata.oneTimePubKey)
		if err != nil {
			return nil, err
		}

		// Store the key for future use
		err = r.SetKey(ctx, m.metadata.conversationID, key)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt the message, which should have been encrypted with the shared key
	msg, err := sym.Decrypt(m.content.ToMessage(), key)
	if err != nil {
		return nil, err
	}

	// Recipient now processes the decrypted information, decides whether
	// to respond, and provides response to send back if that is the case
	shouldReply, b := r.Handle(ctx, msg)
	if !shouldReply {
		return nil, nil
	}

	// Use the same key to encrypt the response
	cipher, err := sym.Encrypt(b, key)
	if err != nil {
		return nil, err
	}

	// Use the recipient's preferred signing key to allow the other
	// party of the conversation to confirm that this is their untampered reply
	return elliptic.NewSigned(r.GetSigningKey(ctx), &Message{
		metadata: &Metadata{
			conversationID: m.metadata.conversationID,
		},
		content: FromMessage(cipher),
	})
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

// PublicKeyInfo contains a PublicKey and the corresponding unique identifier of its PrivateKey
type PublicKeyInfo struct {
	PrivateKeyID elliptic.PrivateKeyID
	PublicKey    *elliptic.PublicKey
}

// NewConversation creates the Signed[Message] that can initiate a conversation with the recipient
func NewConversation(signerPriKey *elliptic.PrivateKey, recipientInfo *PublicKeyInfo, content []byte) (*elliptic.Signed[*Message], []byte, error) {
	return NewConversationWithAlgo(signerPriKey, recipientInfo, content, sym.AESGCM)
}

// NewConversationWithAlgo creates the Signed[Message] that can initiate a conversation with the recipient,
// with the symmetric encryption algorithm specified by the caller
func NewConversationWithAlgo(signerPriKey *elliptic.PrivateKey, recipientInfo *PublicKeyInfo, content []byte, algo sym.Algo) (*elliptic.Signed[*Message], []byte, error) {

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
	return s, key, nil
}
