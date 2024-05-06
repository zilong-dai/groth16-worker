package main

import (
	"log"

	"github.com/zilong-dai/groth16-worker/worker"
)

func main() {
	proverPath := "./testdata"
	verifierPath := "./testdata"

	prover, err := worker.NewGroth16Prover(proverPath)
	if err != nil {
		log.Fatalf("error creating prover: %v", err)
	}

	if err := prover.Setup(); err != nil {
		log.Fatalf("error setting up prover: %v", err)
	}

	if err := prover.Prove(); err != nil {
		log.Fatalf("error running prover: %v", err)
	}

	prover.WriteProvingKey("pk2.key")

	verifier, err := worker.NewGroth16Verifier(verifierPath)
	if err != nil {
		log.Fatalf("error creating verifier: %v", err)
	}

	if err := verifier.Setup(); err != nil {
		log.Fatalf("error setting up verifier: %v", err)
	}

	verifier.Proof = prover.Proof
	verifier.PublicWitness = prover.PublicWitness

	if err := verifier.Verify(); err != nil {
		log.Fatalf("error running verifier: %v", err)
	}
}
