package serialize

import (
	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func SerializeFrMCL(fr *fr.Element) (string, error) {
	frBytes := fr.Bytes()
	return reverseHexString(hex.EncodeToString(frBytes[:])), nil
}

func SerializeFr(fr *fr.Element) string {
	frBytes := fr.Bytes()
	return hex.EncodeToString(frBytes[:])
}
