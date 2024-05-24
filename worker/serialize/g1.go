package serialize

import (
	"encoding/hex"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func SerializeG1MCL(g1 *ArkProofG1) (string, error) {
	cc, _ := new(big.Int).SetString(g1.Y, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g1.X)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return reverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return reverseHexString(g1.X), nil
	}
}

func SerializeG1(g1 *curve.G1Affine) *ArkProofG1 {
	xBytes := g1.X.Bytes()
	yBytes := g1.Y.Bytes()
	return &ArkProofG1{X: hex.EncodeToString(xBytes[:]), Y: hex.EncodeToString(yBytes[:])}
}

func SerializeG1COMMPRESS(g1 *curve.G1Affine) string {
	g1Bytes := g1.Bytes()
	return hex.EncodeToString(g1Bytes[:])
}
