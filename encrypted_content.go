package msg

import (
	"crypto/sha256"

	he "github.com/secure-conversation/elliptic"
	hs "github.com/secure-conversation/sym"
)

// EncryptedContent holds the details of a message that has been
// encrypted using the specified Algo
type EncryptedContent struct {
	Algo       hs.Algo `json:"a"`
	Ciphertext []byte  `json:"c"`
	Nonce      []byte  `json:"n"`
}

func (e *EncryptedContent) Collect() []byte {
	hash := sha256.New()
	hash.Write([]byte(e.Algo.String()))
	hash.Write(he.SigningMaterialSpacer())
	hash.Write(e.Nonce)
	hash.Write(he.SigningMaterialSpacer())
	hash.Write(e.Ciphertext)
	return hash.Sum(he.SigningMaterialSpacer())
}

// ToMessage simplifies work to decrypt
func (e *EncryptedContent) ToMessage() *hs.Message {
	return &hs.Message{
		Algo:       e.Algo,
		Ciphertext: e.Ciphertext,
		Nonce:      e.Nonce,
	}
}

// FromMessage simplifies translation to the EncryptedMessage type
func FromMessage(msg *hs.Message) *EncryptedContent {
	return &EncryptedContent{
		Algo:       msg.Algo,
		Ciphertext: msg.Ciphertext,
		Nonce:      msg.Nonce,
	}
}

// NewEncryptedContent creates a new instance of EncryptedContent
func NewEncryptedContent(msg, key []byte) (*EncryptedContent, error) {
	return NewEncryptedContentWithAlgo(msg, key, hs.AESGCM)
}

// NewEncryptedContentWithAlgo creates a new instance of EncryptedContent
func NewEncryptedContentWithAlgo(msg, key []byte, algo hs.Algo) (*EncryptedContent, error) {
	m, err := hs.EncryptUsingAlgo(msg, key, algo)
	if err != nil {
		return nil, err
	}
	return &EncryptedContent{
		Algo:       m.Algo,
		Ciphertext: m.Ciphertext,
		Nonce:      m.Nonce,
	}, nil
}
