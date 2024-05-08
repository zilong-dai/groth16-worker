package main

import (
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/groth16-worker/worker"
)

func main() {
	// reference: https://github.com/cf/gnark-plonky2-verifier/blob/feat/poseidon-bls12-381/benchmark.go

	workerpath := "./testdata/groth16"
	proverPath := "./testdata/groth16"
	verifierPath := "./testdata/groth16"
	pkpath := "./testdata/groth16/proving.key2"
	vkpath := "./testdata/groth16/verifying.key2"
	proofpath := "./testdata/groth16/proof.proof2"
	publicinputpath := "./testdata/groth16/witness2"
	circuitpath := "./testdata/groth16/circuit2"

	curveId := ecc.BLS12_381

	{
		// setup, save pk, vk and circuit
		setupworker, err := worker.NewGroth16Worker(workerpath, curveId)
		if err != nil {
			log.Fatalf("error creating setup worker: %v", err)
		}

		// about 15mins to setup
		fmt.Println("setup start", time.Now())
		if err := setupworker.Setup(); err != nil {
			log.Fatalf("error setting up worker: %v", err)
		}

		if err := setupworker.WriteProvingKey(pkpath); err != nil {
			log.Fatalf("error writing proving key: %v", err)
		}
		if err := setupworker.WriteVerifyingKey(vkpath); err != nil {
			log.Fatalf("error writing verifying key: %v", err)
		}
		if err := setupworker.WriteCircuit(circuitpath); err != nil {
			log.Fatalf("error writing circuit: %v", err)
		}
	}

	prover, err := worker.NewGroth16Prover(proverPath, curveId)
	if err != nil {
		log.Fatalf("error creating prover: %v", err)
	}

	// read pk, about 5mins for raw pk, 15mins for compressed pk
	fmt.Println("Read proving key start", time.Now())
	if err := prover.ReadProvingKey(pkpath); err != nil {
		log.Fatalf("error reading proving key: %v", err)
	}
	fmt.Println("Read proving key end", time.Now())

	// read circuit
	if err := prover.ReadCircuit(circuitpath); err != nil {
		log.Fatalf("error reading circuit: %v", err)
	}

	// generate witness
	if err := prover.GenerateWitness(); err != nil {
		log.Fatalf("error generating witness: %v", err)
	}

	fmt.Println("prove start", time.Now())
	if err := prover.Prove(); err != nil {
		log.Fatalf("error running prover: %v", err)
	}

	fmt.Println("prove end", time.Now())

	prover.WriteProof(proofpath)
	prover.WritePublicInputs(publicinputpath)

	verifier, err := worker.NewGroth16Verifier(verifierPath, curveId)
	if err != nil {
		log.Fatalf("error creating verifier: %v", err)
	}

	if err := verifier.ReadVerifyingKey(vkpath); err != nil {
		log.Fatalf("error reading verifying key: %v", err)
	}
	if err := verifier.ReadProof(proofpath); err != nil {
		log.Fatalf("error reading proof: %v", err)
	}
	if err := verifier.ReadPublicInputs(publicinputpath); err != nil {
		log.Fatalf("error reading public inputs: %v", err)
	}

	if err := verifier.Verify(); err != nil {
		log.Fatalf("error running verifier: %v", err)
	}
}
