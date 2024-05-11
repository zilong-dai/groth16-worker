package cmd

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/spf13/cobra"
	"github.com/zilong-dai/gorth16-worker/utils"
)

var COMMON_CIRCUIT_DATA_FILE = utils.COMMON_CIRCUIT_DATA_FILE
var PROOF_WITH_PUBLIC_INPUTS_FILE = utils.PROOF_WITH_PUBLIC_INPUTS_FILE
var VERIFIER_ONLY_CIRCUIT_DATA_FILE = utils.VERIFIER_ONLY_CIRCUIT_DATA_FILE

var CIRCUIT_PATH string = utils.CIRCUIT_PATH
var VK_PATH string = utils.VK_PATH
var PK_PATH string = utils.PK_PATH
var PROOF_PATH string = utils.PROOF_PATH
var WITNESS_PATH string = utils.WITNESS_PATH

var CURVE_ID ecc.ID = utils.CURVE_ID

var cmd = &cobra.Command{
	Use: "groth16-worker",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Groth16 Worker CLI")
	},
}

func init() {
	cmd.AddCommand(buildCmd)
	cmd.AddCommand(proveCmd)
	cmd.AddCommand(verifyCmd)
}

func Execute() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
