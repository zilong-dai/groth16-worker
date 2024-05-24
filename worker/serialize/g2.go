package serialize

import (
	"encoding/hex"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func SerializeG2MCL(g2 *ArkProofG2) (string, error) {
	cc, _ := new(big.Int).SetString(g2.Y.A0, 16)
	var elementY fp.Element
	elementY.SetString(cc.String())
	if isOddFp(&elementY) {
		xBytes, err := hex.DecodeString(g2.X.A1)
		if err != nil {
			return "", err
		}
		xBytes[0] |= 0x80
		return reverseHexString(g2.X.A0) + reverseHexString(hex.EncodeToString(xBytes)), nil
	} else {
		return reverseHexString(g2.X.A0) + reverseHexString(g2.X.A1), nil
	}
}

func SerializeG2(g2 *curve.G2Affine) *ArkProofG2 {
	xBytes1 := g2.X.A1.Bytes()
	xBytes0 := g2.X.A0.Bytes()
	yBytes1 := g2.Y.A1.Bytes()
	yBytes0 := g2.Y.A0.Bytes()

	return &ArkProofG2{X: ArkProofE2{A0: hex.EncodeToString(xBytes0[:]), A1: hex.EncodeToString(xBytes1[:])}, Y: ArkProofE2{A0: hex.EncodeToString(yBytes0[:]), A1: hex.EncodeToString(yBytes1[:])}}
}

func SerializeG2COMMPRESS(g2 *curve.G2Affine) string {
	g1Bytes := g2.Bytes()
	return hex.EncodeToString(g1Bytes[:])
}
