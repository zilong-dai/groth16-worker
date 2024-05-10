package cmd

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/spf13/cobra"
	// "github.com/succinctlabs/sp1-recursion-gnark/sp1"
	// "github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

var verifyCmdDataDir string

func init() {
	verifyCmd.Flags().StringVar(&verifyCmdDataDir, "data", "", "")
}

var verifyCmd = &cobra.Command{
	Use: "verify",
	Run: func(cmd *cobra.Command, args []string) {
		// Sanity check the required arguments have been provided.
		if verifyCmdDataDir == "" {
			panic("--data is required")
		}

		// Read the proof.
		proof, err := ReadProof(CURVE_ID, verifyCmdDataDir+"/"+PROOF_PATH)
		if err != nil {
			panic(err)
		}

		// Read the verifier key.
		vk, err := ReadVerifyingKey(CURVE_ID, verifyCmdDataDir+"/"+VK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the public witness.
		publicWitness, err := ReadPublicInputs(CURVE_ID, verifyCmdDataDir+"/"+WITNESS_PATH)
		if err != nil {
			panic(err)
		}

		// Verify proof.
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}

	},
}
