package utils

import "github.com/consensys/gnark-crypto/ecc"

var COMMON_CIRCUIT_DATA_FILE = "common_circuit_data.json"
var PROOF_WITH_PUBLIC_INPUTS_FILE = "proof_with_public_inputs.json"
var VERIFIER_ONLY_CIRCUIT_DATA_FILE = "verifier_only_circuit_data.json"

// var VERIFIER_CONTRACT_PATH string = "SP1Verifier.sol"
var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"
var PROOF_PATH string = "proof_groth16.bin"
var WITNESS_PATH string = "witness_groth16.bin"

var CURVE_ID ecc.ID = ecc.BN254
