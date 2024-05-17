package cmd

import (
	"math/big"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var buildCmdDataDir string

func init() {
	buildCmd.Flags().StringVar(&buildCmdDataDir, "data", "", "")
}

var buildCmd = &cobra.Command{
	Use: "build",
	Run: func(cmd *cobra.Command, args []string) {
		// Sanity check the required arguments have been provided.
		if buildCmdDataDir == "" {
			panic("--data is required")
		}

		// Read the file.
		if err := utils.CheckPlonky2Path(buildCmdDataDir); err != nil {
			panic("plonky2 data is missing")
		}
		commonCircuitData := types.ReadCommonCircuitData(filepath.Join(buildCmdDataDir, COMMON_CIRCUIT_DATA_FILE))
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

		circuit := utils.CRVerifierCircuit{
			PublicInputs:            []frontend.Variable{blockStateHash, sighash},
			Proof:                   proofWithPis.Proof,
			OriginalPublicInputs:    proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		// Compile the circuit.
		r1cs, err := frontend.Compile(CURVE_ID.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			panic(err)
		}

		// Perform the trusted setup.
		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			panic(err)
		}

		// Write the R1CS.
		if err := utils.WriteCircuit(r1cs, buildCmdDataDir+"/"+CIRCUIT_PATH); err != nil {
			panic(err)
		}

		// Write the verifier key.
		if err := utils.WriteVerifyingKey(vk, buildCmdDataDir+"/"+VK_PATH); err != nil {
			panic(err)
		}

		// Write the proving key.
		if err := utils.WriteProvingKey(pk, buildCmdDataDir+"/"+PK_PATH); err != nil {
			panic(err)
		}
	},
}
