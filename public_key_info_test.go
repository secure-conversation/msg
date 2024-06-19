package msg

import (
	"testing"

	"github.com/secure-conversation/elliptic"
	"github.com/secure-conversation/ident"
)

func TestUnMarshalPublicKeyInfo(t *testing.T) {

	msg := []byte("Hungry brown fox")

	var signature []byte

	var b []byte
	var id elliptic.PrivateKeyID

	{
		c, err := elliptic.NewCurve(elliptic.CurveP384)
		if err != nil {
			t.Fatal(err)
		}

		key, err := c.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		id = key.ID()

		signature, err = key.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}

		p := &PublicKeyInfo{
			PrivateKeyID: key.ID(),
			PublicKey:    key.PublicKey(),
		}

		b, err = p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
	}

	p, err := UnMarshalPublicKeyInfo(b)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.PublicKey.Verify(signature, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("unexpected verification failure")
	}

	if !ident.EqualValueID(id, p.PrivateKeyID) {
		t.Fatal("unexpected KeyID match failure")
	}
}

func TestPublicKeyInfo(t *testing.T) {

	c, err := elliptic.NewCurve(elliptic.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := c.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	p := &PublicKeyInfo{
		PrivateKeyID: privKey.ID(),
		PublicKey:    privKey.PublicKey(),
	}

	s, err := elliptic.NewSigned(privKey, p)
	if err != nil {
		t.Fatal(err)
	}

	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	s1, err := elliptic.ParseSigned[*PublicKeyInfo](b)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := s1.Verify(privKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("unexpected failure to verify signature")
	}
}
