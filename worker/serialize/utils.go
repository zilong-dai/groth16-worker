package serialize

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

func isOddFp(x *fp.Element) bool {
	return x.BigInt(big.NewInt(0)).Bit(0) == 1
}

func reverseHexString(hexStr string) string {
	reversed := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		reversed[i] = hexStr[len(hexStr)-i-2]
		reversed[i+1] = hexStr[len(hexStr)-i-1]
	}
	return string(reversed)
}

func Base10ToHex(base10 string, padLength int) string {
	n := new(big.Int)
	n.SetString(base10, 10)
	return fmt.Sprintf("%0"+fmt.Sprintf("%d", padLength)+"x", n)

}
