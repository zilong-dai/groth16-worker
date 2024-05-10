package cmd

import (
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/spf13/cobra"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	// "github.com/spf13/cobra"
	// "github.com/succinctlabs/sp1-recursion-gnark/sp1"
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
		if err := CheckPlonky2Path(buildCmdDataDir); err != nil {
			panic("plonky2 data is missing")
		}
		commonCircuitData := types.ReadCommonCircuitData(filepath.Join(buildCmdDataDir, COMMON_CIRCUIT_DATA_FILE))
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(buildCmdDataDir, PROOF_WITH_PUBLIC_INPUTS_FILE)))
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(buildCmdDataDir, VERIFIER_ONLY_CIRCUIT_DATA_FILE)))

		circuit := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
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
		if err := WriteCircuit(r1cs, buildCmdDataDir+"/"+CIRCUIT_PATH); err != nil {
			panic(err)
		}

		// Write the verifier key.
		if err := WriteVerifyingKey(vk, buildCmdDataDir+"/"+VK_PATH); err != nil {
			panic(err)
		}

		// Write the proving key.
		if err := WriteProvingKey(pk, buildCmdDataDir+"/"+PK_PATH); err != nil {
			panic(err)
		}
	},
}
