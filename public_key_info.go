package msg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/secure-conversation/elliptic"
)

// PublicKeyInfo contains a PublicKey and the corresponding unique identifier of its PrivateKey
type PublicKeyInfo struct {
	PrivateKeyID elliptic.PrivateKeyID
	PublicKey    *elliptic.PublicKey
}

// Marshal encodes the instance to JSON
func (p *PublicKeyInfo) Marshal() ([]byte, error) {
	pi := &pubKeyInfo{
		ID: base64.RawStdEncoding.EncodeToString(p.PrivateKeyID[:]),
	}
	if p.PublicKey != nil {
		b, err := p.PublicKey.Marshal()
		if err != nil {
			return nil, err
		}
		pi.Key = string(b)
	}
	return json.Marshal(pi)
}

// UnMarshal decodes from JSON, populating this instance
func (p *PublicKeyInfo) UnMarshal(data []byte) error {
	var pi pubKeyInfo
	err := json.Unmarshal(data, &pi)
	if err != nil {
		return err
	}

	keyID, err := base64.RawStdEncoding.DecodeString(pi.ID)
	if err != nil {
		return err
	}
	copy(p.PrivateKeyID[:], keyID)

	if pi.Key != "" {
		key, err := elliptic.UnMarshalPublicKey([]byte(pi.Key))
		if err != nil {
			return err
		}
		p.PublicKey = key
	}

	return nil
}

// New returns a new instance of PublicKeyInfo
func (p *PublicKeyInfo) New() any {
	return &PublicKeyInfo{}
}

// Collect ensures consistency of signature generation
func (p *PublicKeyInfo) Collect() []byte {
	h := sha256.New()
	h.Write(p.PrivateKeyID[:])
	h.Write(elliptic.SigningMaterialSpacer())
	if p.PublicKey != nil {
		b, _ := p.PublicKey.Marshal()
		h.Write(b)
	}
	h.Write(elliptic.SigningMaterialSpacer())
	return h.Sum(nil)
}

// UnMarshalPublicKeyInfo creates an instance of PublicKeyInfo from JSON
func UnMarshalPublicKeyInfo(data []byte) (*PublicKeyInfo, error) {
	var pubInfo PublicKeyInfo
	err := pubInfo.UnMarshal(data)
	if err != nil {
		return nil, err
	}

	return &pubInfo, nil
}

type pubKeyInfo struct {
	ID  string `json:"i"`
	Key string `json:"k"`
}
