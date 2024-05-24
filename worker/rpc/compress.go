package rpc

import (
	"encoding/hex"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func isOddFp(x *fp.Element) bool {
	return x.BigInt(big.NewInt(0)).Bit(0) == 1
}

func ReverseHexString(hexStr string) string {
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)
}
func SerializeG1(g1 *curve.G1Affine) (string, error) {
	xBytes := g1.X.Bytes()
	if isOddFp(&g1.Y) {
		xBytes[0] |= 0x80
	}
	return ReverseHexString(hex.EncodeToString(xBytes[:])), nil
}

func SerializeG2(g2 *curve.G2Affine) (string, error) {
	xBytes1 := g2.X.A1.Bytes()
	xBytes0 := g2.X.A0.Bytes()
	if isOddFp(&g2.Y.A0) {
		xBytes1[0] |= 0x80
	}
	return ReverseHexString(hex.EncodeToString(xBytes0[:])) + ReverseHexString(hex.EncodeToString(xBytes1[:])), nil
}

func SerializeFr(fr *fr.Element) (string, error) {
	frBytes := fr.Bytes()
	return ReverseHexString(hex.EncodeToString(frBytes[:])), nil
}
