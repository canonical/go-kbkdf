// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package hmac_prf implements HMAC based pseudo-random functions (PRFs).

These can be used by the key derivation functions described in NIST SP-800-108.
Note that the application must ensure that the required digest algorithm is
imported into the final binary. The package does not do that.
*/
package hmac_prf

import (
	"crypto"
	"crypto/hmac"

	"github.com/canonical/go-kbkdf"
)

type prf crypto.Hash

func (p prf) Len() uint32 {
	return uint32(crypto.Hash(p).Size())
}

func (p prf) Run(s, x []byte) []byte {
	h := hmac.New(crypto.Hash(p).New, s)
	h.Write(x)
	return h.Sum(nil)
}

// New creates a new HMAC based PRF using the supplied digest algorithm.
func New(h crypto.Hash) kbkdf.PRF {
	return prf(h)
}

var (
	// SHA1 is a HMAC-SHA1 PRF
	SHA1 = New(crypto.SHA1)

	// SHA224 is a HMAC-SHA224 PRF
	SHA224 = New(crypto.SHA224)

	// SHA256 is a HMAC-SHA256 PRF
	SHA256 = New(crypto.SHA256)

	// SHA384 is a HMAC-SHA384 PRF
	SHA384 = New(crypto.SHA384)

	// SHA512 is a HMAC-SHA512 PRF
	SHA512 = New(crypto.SHA512)
)
