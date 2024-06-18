package msg

import (
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
	b, err := p.PublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	pi.Key = string(b)
	return json.Marshal(pi)
}

// UnMarshalPublicKeyInfo creates an instance of PublicKeyInfo from JSON
func UnMarshalPublicKeyInfo(data []byte) (*PublicKeyInfo, error) {
	var pi pubKeyInfo
	err := json.Unmarshal(data, &pi)
	if err != nil {
		return nil, err
	}

	id, err := base64.RawStdEncoding.DecodeString(pi.ID)
	if err != nil {
		return nil, err
	}
	key, err := elliptic.UnMarshalPublicKey([]byte(pi.Key))
	if err != nil {
		return nil, err
	}

	p := &PublicKeyInfo{
		PublicKey: key,
	}
	copy(p.PrivateKeyID[:], id)

	return p, nil
}

type pubKeyInfo struct {
	ID  string `json:"i"`
	Key string `json:"k"`
}
