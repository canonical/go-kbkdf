// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package kbkdf implements the key derivation functions described in NIST SP-800-108.

All 3 modes are implemented - counter, feedback and pipeline.

The counter mode is used extensively in the reference TPM implementation.
*/
package kbkdf

import (
	"bytes"
	"encoding/binary"
)

func fixedBytes(label, context []byte, bitLength uint32) []byte {
	var res bytes.Buffer
	res.Write(label)
	res.Write([]byte{0})
	res.Write(context)
	binary.Write(&res, binary.BigEndian, bitLength)
	return res.Bytes()
}

func commonKDF(prfLen uint32, bitLength uint32, fn func(uint32) []byte) []byte {
	n := (bitLength + prfLen - 1) / prfLen // The number of iterations required

	var res bytes.Buffer

	for i := uint32(1); i <= n; i++ {
		res.Write(fn(i))
	}

	return res.Bytes()[:(bitLength+7)/8]
}

func counterModeKeyInternal(prf PRF, key, fixed []byte, bitLength uint32) []byte {
	return commonKDF(prf.Size(), bitLength, func(i uint32) []byte {
		var x bytes.Buffer
		binary.Write(&x, binary.BigEndian, i)
		x.Write(fixed)
		return prf.Run(key, x.Bytes())
	})
}

// CounterModeKey derives a key of the specified length using the counter mode
// function described in NIST SP-800-108, using the supplied PRF, secret key and
// other input parameters.
func CounterModeKey(prf PRF, key, label, context []byte, bitLength uint32) []byte {
	return counterModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), bitLength)
}

// IterationCounterMode defines whether the iteration counter is included
// in the feedback and double-pipeline KDFs
type IterationCounterMode bool

const (
	OmitIterationCounter    IterationCounterMode = false
	IncludeIterationCounter IterationCounterMode = true
)

func feedbackModeKeyInternal(prf PRF, key, fixed, iv []byte, bitLength uint32, iterationCounterMode IterationCounterMode) []byte {
	k := iv

	return commonKDF(prf.Size(), bitLength, func(i uint32) []byte {
		var x bytes.Buffer
		x.Write(k)
		if iterationCounterMode == IncludeIterationCounter {
			binary.Write(&x, binary.BigEndian, i)
		}
		x.Write(fixed)

		k = prf.Run(key, x.Bytes())
		return k
	})
}

// FeebackModeKey derives a key of the specified length using the feedback mode
// function described in NIST SP-800-108, using the supplied PRF, secret key and
// other input parameters.
//
// The iterationCounterMode argument specifies whether the iteration counter should be
// included as an input to the PRF.
func FeedbackModeKey(prf PRF, key, label, context, iv []byte, bitLength uint32, iterationCounterMode IterationCounterMode) []byte {
	return feedbackModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), iv, bitLength, iterationCounterMode)
}

func pipelineModeKeyInternal(prf PRF, key, fixed []byte, bitLength uint32, iterationCounterMode IterationCounterMode) []byte {
	a := fixed

	return commonKDF(prf.Size(), bitLength, func(i uint32) []byte {
		a = prf.Run(key, a)

		var x bytes.Buffer
		x.Write(a)
		if iterationCounterMode == IncludeIterationCounter {
			binary.Write(&x, binary.BigEndian, i)
		}
		x.Write(fixed)

		return prf.Run(key, x.Bytes())
	})
}

// PipelineModeKey derives a key of the specified length using the double-pipeline
// iteration mode function described in NIST SP-800-108, using the supplied PRF,
// secret key and other input parameters.
//
// The iterationCounterMode argument specifies whether the iteration counter should be
// included as an input to the PRF.
func PipelineModeKey(prf PRF, key, label, context []byte, bitLength uint32, iterationCounterMode IterationCounterMode) []byte {
	return pipelineModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), bitLength, iterationCounterMode)
}
