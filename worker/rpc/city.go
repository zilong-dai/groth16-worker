package rpc

import (
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
)

type CityGroth16ProofData struct {
	PiA          string `json:"pi_a"`
	PiBA0        string `json:"pi_b_a0"`
	PiBA1        string `json:"pi_b_a1"`
	PiC          string `json:"pi_c"`
	PublicInput0 string `json:"public_input_0"`
	PublicInput1 string `json:"public_input_1"`
}

func ToJsonCityProof(p *groth16_bls12381.Proof, witness []fr.Element) (*CityGroth16ProofData, error) {

	piASerialized, err := SerializeG1(&p.Ar)
	if err != nil {
		return nil, err
	}

	piBSerialized, err := SerializeG2(&p.Bs)
	if err != nil {
		return nil, err
	}

	piCSerialized, err := SerializeG1(&p.Krs)
	if err != nil {
		return nil, err
	}
	pub0, err := SerializeFr(&witness[0])
	if err != nil {
		return nil, err
	}

	pub1, err := SerializeFr(&witness[1])
	if err != nil {
		return nil, err
	}

	return &CityGroth16ProofData{
		piASerialized,
		piBSerialized[:96],
		piBSerialized[96:],
		piCSerialized,
		pub0,
		pub1,
	}, nil
}
