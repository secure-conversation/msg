package msg

import "github.com/secure-conversation/ident"

// Signature represents a cryptographic signature of some content
type Signature []byte

// ConversationIDLength is the length of a unique conversation identifier
const ConversationIDLength = 16

// ConversationID represents a unique identifier of a single conversation between two identities
type ConversationID [ConversationIDLength]byte

// Copy returns a new ConversationID initialised to the same value
func (c ConversationID) Copy() ConversationID {
	return ident.CopyID(c)
}

// Equals returns true if the ConversationID instances are the same
func (c ConversationID) Equals(other ConversationID) bool {
	return ident.EqualValueID(c, other)
}

// IsEmpty returns true if the ConversationID is uninitialised
func (c ConversationID) IsEmpty() bool {
	return ident.EmptyID(c)
}

// NewConversationID creates a unique, time-aligned identifier to a high level of entropy
func NewConversationID() ConversationID {
	return ident.NewID[ConversationID]()
}

// IdentityIDLength is the length of a unique identifier for an identity owning private keys
const IdentityIDLength = 16

// IdentityID represents a unique identifier for an identity that owns private keys
type IdentityID [IdentityIDLength]byte

// Copy returns a new IdentityID initialised to the same value
func (i IdentityID) Copy() IdentityID {
	return ident.CopyID(i)
}

// Equals returns true if the IdentityID instances are the same
func (i IdentityID) Equals(other IdentityID) bool {
	return ident.EqualValueID(i, other)
}

// IsEmpty returns true if the IdentityID is uninitialised
func (i IdentityID) IsEmpty() bool {
	return ident.EmptyID(i)
}

// NewIdentityID creates a unique, time-aligned identifier to a high level of entropy
func NewIdentityID() IdentityID {
	return ident.NewID[IdentityID]()
}
