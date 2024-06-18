msg
===

[![Go Doc](https://pkg.go.dev/badge/github.com/secure-conversation/msg.svg)](https://pkg.go.dev/github.com/secure-conversation/msg)
[![Go Report Card](https://goreportcard.com/badge/github.com/secure-conversation/msg)](https://goreportcard.com/report/github.com/secure-conversation/msg)

This package allows the creation of a secure conversation between two parties, independently of the security provided by the underlying transport.

Each party uses Elliptic Curve encryption to create PublicKeys which can be used both to generate ECDH shared secrets, but also for signing to provide authentication and intactness of message content.

Message transfers occur as part of conversations, each with a unique identifier, allowing multiple concurrent and independently secured conversations between the two parties.

JSON is used for `Message` serialisation, for portability of behaviour across different languages (only Go is implemented here).

The `Recipient` interface exposes the minimal set of functions required to successfully receive, process and optionally reply to any messages.

Example:

```go
package main

import (
  "fmt"

  "github.com/secure-conversation/elliptic"
  "github.com/secure-conversation/msg"
)

func main() {
  c, _ := elliptic.NewCurve(elliptic.CurveP256)

  // Private keys are smanaged securely by each party, and provide identity
  senderIdentityKey, _ := c.GenerateKey()
  recipientIdentityKey, _ := c.GenerateKey()

  // Published public key information allows ECDH secret generation etc.
  recipientPubInfo := &msg.PublicKeyInfo{
    PrivateKeyID: recipientIdentityKey.ID(),
    PublicKey:    recipientIdentityKey.PublicKey(),
  }

  // sender transfers Hello World to the recipient
  msg, _, _ := msg.NewConversation(senderIdentityKey, recipientPubInfo, []byte("Hello World"))

  b, _ := msg.Marshal()

  fmt.Println(string(b))
}
```
