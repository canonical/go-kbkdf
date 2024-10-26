// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package kbkdf

// PRF represents a pseudorandom function.
type PRF interface {
	// Size returns the output length of this PRF.
	Size() uint32

	// Run computes bytes for the supplied seed and input value.
	Run(s, x []byte) []byte
}
