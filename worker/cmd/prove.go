package cmd

import (
	"math/big"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var proveCmdDataDir string

func init() {
	proveCmd.Flags().StringVar(&proveCmdDataDir, "data", "", "")
}

var proveCmd = &cobra.Command{
	Use: "prove",
	Run: func(cmd *cobra.Command, args []string) {
		// Sanity check the required arguments have been provided.
		if proveCmdDataDir == "" {
			panic("--data is required")
		}

		// Read the R1CS.
		r1cs, err := utils.ReadCircuit(CURVE_ID, proveCmdDataDir+"/"+CIRCUIT_PATH)
		if err != nil {
			panic(err)
		}

		// Read the proving key.
		pk, err := utils.ReadProvingKey(CURVE_ID, proveCmdDataDir+"/"+PK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the verifier key.
		vk, err := utils.ReadVerifyingKey(CURVE_ID, proveCmdDataDir+"/"+VK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the file.
		if err := utils.CheckPlonky2Path(proveCmdDataDir); err != nil {
			panic("plonky2 data is missing")
		}

		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(buildCmdDataDir, VERIFIER_ONLY_CIRCUIT_DATA_FILE)))

		rawProofWithPis := types.ReadProofWithPublicInputs(filepath.Join(buildCmdDataDir, PROOF_WITH_PUBLIC_INPUTS_FILE))
		proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

		two_to_63 := new(big.Int).SetUint64(1 << 63)

		blockStateHashAcc := big.NewInt(0)
		sighashAcc := big.NewInt(0)
		for i := 3; i >= 0; i-- {
			blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two_to_63)
			blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
		}
		for i := 7; i >= 4; i-- {
			sighashAcc = new(big.Int).Mul(sighashAcc, two_to_63)
			sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
		}
		blockStateHash := frontend.Variable(blockStateHashAcc)
		sighash := frontend.Variable(sighashAcc)

		assignment := utils.CRVerifierCircuit{
			PublicInputs:            []frontend.Variable{blockStateHash, sighash},
			Proof:                   proofWithPis.Proof,
			OriginalPublicInputs:    proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
		}
		witness, err := frontend.NewWitness(&assignment, CURVE_ID.ScalarField())
		if err != nil {
			panic(err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			panic(err)
		}

		// Verify proof.
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}

		// Serialize the proof to a file.
		if err := utils.WriteProof(proof, proveCmdDataDir+"/"+PROOF_PATH); err != nil {
			panic(err)
		}

		if err := utils.WritePublicInputs(publicWitness, proveCmdDataDir+"/"+WITNESS_PATH); err != nil {
			panic(err)
		}
	},
}
