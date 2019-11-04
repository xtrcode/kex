/*
	This is free and unencumbered software released into the public domain.

	Anyone is free to copy, modify, publish, use, compile, sell, or
	distribute this software, either in source code form or as a compiled
	binary, for any purpose, commercial or non-commercial, and by any
	means.

	In jurisdictions that recognize copyright laws, the author or authors
	of this software dedicate any and all copyright interest in the
	software to the public domain. We make this dedication for the benefit
	of the public at large and to the detriment of our heirs and
	successors. We intend this dedication to be an overt act of
	relinquishment in perpetuity of all present and future rights to this
	software under copyright law.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
	IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
	ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
	OTHER DEALINGS IN THE SOFTWARE.

	For more information, please refer to <http://unlicense.org/>
*/

package kex

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/gob"
	"errors"
	"math/big"
)

const (
	P224 int = iota
	P256 int = iota
	P386 int = iota
	P512 int = iota
)

type Kex struct {
	Curve  elliptic.Curve
	SK     *ecdsa.PrivateKey
	X, Y   *big.Int
	Scalar *big.Int
}

func NewP224() *Kex {
	k, _ := NewKex(P224)
	return k
}

func NewP256() *Kex {
	k, _ := NewKex(P256)
	return k
}

func NewP386() *Kex {
	k, _ := NewKex(P386)
	return k
}

func NewP512() *Kex {
	k, _ := NewKex(P512)
	return k
}

func NewKex(curveType int) (*Kex, error) {
	var (
		curve elliptic.Curve
	)

	switch curveType {
	case P224:
		curve = elliptic.P224()
	case P256:
		curve = elliptic.P256()
	case P386:
		curve = elliptic.P384()
	case P512:
		curve = elliptic.P521()
	default:
		return nil, errors.New("Unknown elliptic curve.")
	}

	sk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Kex{
		Curve: curve,
		SK:    sk,
		X:     big.NewInt(0),
		Y:     big.NewInt(0),
	}, nil
}

// Encode encodes your public keys X & Y values using gob
// to transmit them to your partner/server/whatever.
func (k *Kex) Encode() ([]byte, error) {
	buffer := new(bytes.Buffer)

	e := gob.NewEncoder(buffer)
	if err := e.Encode([][]byte{k.SK.PublicKey.X.Bytes(), k.SK.PublicKey.Y.Bytes()}); err != nil {
		return nil, errors.New("Encoding public key failed.")
	}

	return buffer.Bytes(), nil
}

// Decode decodes the received public key X & Y values using gob
// to be able to generate your shared secret.
func (k *Kex) Decode(encodedPK []byte) error {
	// reset old pk
	k.X = big.NewInt(0)
	k.Y = big.NewInt(0)

	buffer := new(bytes.Buffer)
	buffer.Write(encodedPK)

	var decodedPK [][]byte

	d := gob.NewDecoder(buffer)
	if err := d.Decode(&decodedPK); err != nil {
		return errors.New("Decoding public key failed")
	}

	k.X.SetBytes(decodedPK[0])
	k.Y.SetBytes(decodedPK[1])

	return nil
}

// Calculate shared secret.
func (k *Kex) Calculate() {
	k.Scalar, _ = k.SK.PublicKey.Curve.ScalarMult(k.X, k.Y, k.SK.D.Bytes())
}

func (k *Kex) Sum224() [sha256.Size224]byte {
	k.Calculate()
	return sha256.Sum224(k.Scalar.Bytes())
}

func (k *Kex) Sum256() [sha256.Size]byte {
	k.Calculate()
	return sha256.Sum256(k.Scalar.Bytes())
}

func (k *Kex) Sum512() [sha512.Size]byte {
	k.Calculate()
	return sha512.Sum512(k.Scalar.Bytes())
}
