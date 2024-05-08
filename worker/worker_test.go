package worker_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/groth16-worker/worker"
)

func TestGroth16Verifier(t *testing.T) {
	verifierPath := "../testdata"

	verifier, err := worker.NewGroth16Verifier(verifierPath, ecc.BLS12_381)

	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Setup(); err != nil {
		t.Fatal(err)
	}

}

func TestGroth16Prover(t *testing.T) {
	proverPath := "../testdata"

	prover, err := worker.NewGroth16Prover(proverPath, ecc.BLS12_381)

	if err != nil {
		t.Fatal(err)
	}

	if err := prover.Setup(); err != nil {
		t.Fatal(err)
	}
}
