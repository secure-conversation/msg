package msg

import (
	"context"

	"github.com/secure-conversation/elliptic"
)

// ConversationManager manages the details for conversations
type ConversationManager interface {
	// GetDetails returns the details for the conversation
	GetDetails(context.Context, ConversationID) (*ConversationDetails, error)
	// SetDetails allows the details of a conversaton to be stored
	SetDetails(context.Context, *ConversationDetails) error
}

// PublicKeyManager manages public keys
type PublicKeyManager interface {
	// GetPrivateKey retrieves a public key based on its associated PrivateKeyID
	GetPublicKey(context.Context, elliptic.PrivateKeyID) (*elliptic.PublicKey, error)
}

// PrivateKeyManager manages private keys
type PrivateKeyManager interface {
	// GetPrivateKey retrieves a private key based on the PrivateKeyID
	GetPrivateKey(context.Context, elliptic.PrivateKeyID) (*elliptic.PrivateKey, error)
}

// Handler provides the mechanism to handle received messages
type Handler interface {
	// Handle is called to allow the Recipient to process and optionally respond to the supplied message
	// Set flag to true if a reply message should be sent, setting to false will mean no message is
	// sent irrespective of whether reply is nil or not.
	Handle(ctx context.Context, data []byte) (flag bool, reply []byte)
}

// Recipient specifies the functions needed to respond to a received Message
type Recipient interface {
	ConversationManager
	PrivateKeyManager
	PublicKeyManager
	Handler
}
