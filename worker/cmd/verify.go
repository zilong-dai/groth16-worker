package cmd

import (
	"github.com/zilong-dai/gorth16-worker/utils"

	"github.com/spf13/cobra"
	"github.com/zilong-dai/gnark/backend/groth16"
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
		proof, err := utils.ReadProof(CURVE_ID, verifyCmdDataDir+"/"+PROOF_PATH)
		if err != nil {
			panic(err)
		}

		// Read the verifier key.
		vk, err := utils.ReadVerifyingKey(CURVE_ID, verifyCmdDataDir+"/"+VK_PATH)
		if err != nil {
			panic(err)
		}

		// Read the public witness.
		publicWitness, err := utils.ReadPublicInputs(CURVE_ID, verifyCmdDataDir+"/"+WITNESS_PATH)
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
