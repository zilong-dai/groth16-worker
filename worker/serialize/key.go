package serialize

import (
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
)

func ToArkVK(vk *groth16_bls12381.VerifyingKey) *ArkHex2VK {
	v := new(ArkHex2VK)
	v.AlphaG1 = *SerializeG1(&vk.G1.Alpha)
	v.BetaG2 = *SerializeG2(&vk.G2.Beta)
	v.GammaG2 = *SerializeG2(&vk.G2.Gamma)
	v.DeltaG2 = *SerializeG2(&vk.G2.Delta)
	v.G1K = make([]ArkProofG1, len(vk.G1.K))
	for i, g := range vk.G1.K {
		v.G1K[i] = *SerializeG1(&g)
	}
	return v
}
