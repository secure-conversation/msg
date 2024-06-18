package msg

import (
	"context"

	"github.com/secure-conversation/elliptic"
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
