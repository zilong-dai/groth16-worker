package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/zilong-dai/gnark-plonky2-verifier/plonk/gates"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark/backend/groth16"
	bls12381 "github.com/zilong-dai/gnark/backend/groth16/bls12-381"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gorth16-worker/utils"
)

func (w *Groth16Prover) Build(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) string {

	commonCircuitData, err := ReadCommonCircuitDataRaw(common_circuit_data)
	if err != nil {
		return "false"
	}
	circuitDataRaw, err := ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)

	if err != nil {
		return "false"
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(circuitDataRaw)

	rawProofWithPis, err := ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	if err != nil {
		return "false"
	}
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	two := big.NewInt(2)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two)
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

	w.r1cs, err = frontend.Compile(w.curveId.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("failed to compile r1cs: %v", err)
		return "false"
	}

	// Perform the trusted setup.
	w.pk, w.vk, err = groth16.Setup(w.r1cs)
	if err != nil {
		fmt.Println("failed to perform trusted setup: %v", err)
		return "false"
	}

	// Write the R1CS.
	if err := utils.WriteCircuit(w.r1cs, KEY_STORE_PATH+"/"+CIRCUIT_FILE); err != nil {
		fmt.Println("failed to write r1cs to %s: %v", KEY_STORE_PATH+"/"+CIRCUIT_FILE, err)
		return "false"
	}

	// Write the verifier key.
	if err := utils.WriteVerifyingKey(w.vk, KEY_STORE_PATH+"/"+VK_FILE); err != nil {
		fmt.Println("failed to write verifier key to %s: %v", KEY_STORE_PATH+"/"+VK_FILE, err)
		return "false"
	}

	// Write the proving key.
	if err := utils.WriteProvingKey(w.pk, KEY_STORE_PATH+"/"+PK_FILE); err != nil {
		fmt.Println("failed to write proving key to %s: %v", KEY_STORE_PATH+"/"+PK_FILE, err)
		return "false"

	}

	return "true"
}

func (w *Groth16Prover) GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) string {

	commonCircuitData, err := ReadCommonCircuitDataRaw(common_circuit_data)
	if err != nil {
		return "false"
	}
	circuitDataRaw, err := ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)

	if err != nil {
		return "false"
	}

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(circuitDataRaw)

	rawProofWithPis, err := ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	if err != nil {
		return "false"
	}
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	two := big.NewInt(2)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two)
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

	assignment := utils.CRVerifierCircuit{
		PublicInputs:            circuit.PublicInputs,
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// ref: https://github.com/Consensys/gnark/issues/1038
	witness, err := frontend.NewWitness(&assignment, w.curveId.ScalarField())
	if err != nil {
		fmt.Println("failed to create witness: %v", err)
		return "false"
	}

	cs, err := frontend.Compile(w.curveId.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("failed to compile r1cs: %v", err)
		return "false"
	}

	proof, err := groth16.Prove(cs, w.pk, witness)
	if err != nil {
		fmt.Println("failed to generate proof: %v", err)
		return "false"
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("failed to generate public witness: %v", err)
		return "false"
	}

	err = groth16.Verify(proof, w.vk, publicWitness)
	if err != nil {
		fmt.Println("failed to generate verify proof: %v", err)
		return "false"
	}

	var g16ProofWithPublicInputs = G16ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: publicWitness,
	}

	proof_bytes, err := json.Marshal(g16ProofWithPublicInputs)
	if err != nil {
		fmt.Println("failed to Marshal G16ProofWithPublicInputs: %v", err)
		return "false"
	}

	return string(proof_bytes)
}

func (w *Groth16Prover) VerifyProof(proofString string) string {
	g16ProofWithPublicInputs := NewG16ProofWithPublicInputs(w.curveId)

	if err := json.Unmarshal([]byte(proofString), g16ProofWithPublicInputs); err != nil {
		fmt.Println("json unmarshal proofString failed %v", err)
		return "false"
	}

	if err := groth16.Verify(g16ProofWithPublicInputs.Proof, w.vk, g16ProofWithPublicInputs.PublicInputs); err != nil {
		fmt.Println("verify proof failed %v", err)
		return "false"
	}
	return "true"
}

func Chunk(str string, chunk int) []string {
	if len(str) < chunk*96 {
		fmt.Println("proof field element string too short")
	}
	res := make([]string, chunk)

	// chunkSize := len(str) / chunk

	for i := 0; i < chunk; i++ {
		res[i] = str[i*96 : (i+1)*96]
	}

	return res
}

func (p G16ProofWithPublicInputs) MarshalJSON() ([]byte, error) {

	proof := p.Proof.(*bls12381.Proof)

	var buf [48 * 2]byte
	var writer bytes.Buffer

	for i := 0; i < len(proof.Commitments); i++ {
		buf = proof.Commitments[i].RawBytes()
		_, err := writer.Write(buf[:])
		if err != nil {
			return nil, err
		}
	}

	pi_a_arr := Chunk(hex.EncodeToString((&proof.Ar).Marshal()), 2)
	pi_b_arr := Chunk(hex.EncodeToString((&proof.Bs).Marshal()), 4)
	pi_c_arr := Chunk(hex.EncodeToString((&proof.Krs).Marshal()), 2)

	var buffer bytes.Buffer
	_, err := p.PublicInputs.WriteTo(&buffer)
	if err != nil {
		return nil, err
	}
	public_inputs_arr := hex.EncodeToString(buffer.Bytes())[24:]

	proof_map := map[string]interface{}{
		"pi_a":          [2]string{pi_a_arr[0], pi_a_arr[1]},
		"pi_b":          [2][2]string{{pi_b_arr[1], pi_b_arr[0]}, {pi_b_arr[3], pi_b_arr[2]}},
		"pi_c":          [2]string{pi_c_arr[0], pi_c_arr[1]},
		"Commitments":   hex.EncodeToString(writer.Bytes()),
		"CommitmentPok": hex.EncodeToString((&proof.CommitmentPok).Marshal()),
		"public_inputs": [2]string{public_inputs_arr[0:64], public_inputs_arr[64:128]},
	}
	return json.Marshal(proof_map)

}

func (p *G16ProofWithPublicInputs) UnmarshalJSON(data []byte) error {
	proof := p.Proof.(*bls12381.Proof)
	var ProofString struct {
		PiA           [2]string    `json:"pi_a"`
		PiB           [2][2]string `json:"pi_b"`
		PiC           [2]string    `json:"pi_c"`
		Commitments   string       `json:"Commitments"`
		CommitmentPok string       `json:"CommitmentPok"`
		PublicInputs  [2]string    `json:"public_inputs"`
	}

	err := json.Unmarshal(data, &ProofString)
	if err != nil {
		return err
	}

	pia_bytes, err := hex.DecodeString(ProofString.PiA[0] + ProofString.PiA[1])
	if err != nil {
		return err
	}
	err = proof.Ar.Unmarshal(pia_bytes)
	if err != nil {
		return err
	}

	pib_bytes, err := hex.DecodeString(ProofString.PiB[0][1] + ProofString.PiB[0][0] + ProofString.PiB[1][1] + ProofString.PiB[1][0])
	if err != nil {
		return err
	}
	err = proof.Bs.Unmarshal(pib_bytes)
	if err != nil {
		return err
	}

	pic_bytes, err := hex.DecodeString(ProofString.PiC[0] + ProofString.PiC[1])
	if err != nil {
		return err
	}
	err = proof.Krs.Unmarshal(pic_bytes)
	if err != nil {
		return err
	}

	com_bytes, err := hex.DecodeString(ProofString.Commitments)
	if err != nil {
		return err
	}
	len := len(com_bytes) / 96
	proof.Commitments = make([]curve.G1Affine, len)
	for i := 0; i < len; i++ {
		err = proof.Commitments[i].Unmarshal(com_bytes[96*i : 96*(i+1)])
		if err != nil {
			return err
		}
	}

	compok_bytes, err := hex.DecodeString(ProofString.CommitmentPok)
	if err != nil {
		return err
	}
	err = proof.CommitmentPok.Unmarshal(compok_bytes)
	if err != nil {
		return err
	}

	// public inputs num 2, witness inputs num 0, vector length 2
	publicinputs_bytes, err := hex.DecodeString("000000020000000000000002" + ProofString.PublicInputs[0] + ProofString.PublicInputs[1])

	if err != nil {
		return err
	}

	reader := bytes.NewReader(publicinputs_bytes)

	if _, err = p.PublicInputs.ReadFrom(reader); err != nil {
		return err
	}

	return nil
}

// type VerifyingKey struct {
// 	// [α]₁, [Kvk]₁
// 	G1 struct {
// 		Alpha       curve.G1Affine
// 		Beta, Delta curve.G1Affine   // unused, here for compatibility purposes
// 		K           []curve.G1Affine // The indexes correspond to the public wires
// 	}

// 	// [β]₂, [δ]₂, [γ]₂,
// 	// -[δ]₂, -[γ]₂: see proof.Verify() for more details
// 	G2 struct {
// 		Beta, Delta, Gamma curve.G2Affine
// 		deltaNeg, gammaNeg curve.G2Affine // not serialized
// 	}

// 	// e(α, β)
// 	e curve.GT // not serialized

// 	CommitmentKey                pedersen.VerifyingKey
// 	PublicAndCommitmentCommitted [][]int // indexes of public/commitment committed variables
// }

// pub struct VerifyingKey<E: Pairing> {
//     pub alpha_g1: E::G1Affine,
//     pub beta_g2: E::G2Affine,
//     pub gamma_g2: E::G2Affine,
//     pub delta_g2: E::G2Affine,
//     pub gamma_abc_g1: Vec<E::G1Affine>,
// }

func (gvk G16VerifyingKey) MarshalJSON() ([]byte, error) {
	vk := gvk.VK.(*bls12381.VerifyingKey)
	var buf [48 * 2]byte

	gamma_abc_g1_arr := make([][]string, len(vk.G1.K))
	for i := 0; i < len(vk.G1.K); i++ {
		gamma_abc_g1_arr[i] = make([]string, 2)
	}
	for i := 0; i < len(vk.G1.K); i++ {
		buf = vk.G1.K[i].RawBytes()
		gamma_abc_g1_arr[i][0] = hex.EncodeToString(buf[:])[0:96]
		gamma_abc_g1_arr[i][1] = hex.EncodeToString(buf[:])[96:192]
	}

	var comkey_writer bytes.Buffer

	vk.CommitmentKey.WriteRawTo(&comkey_writer)

	alpha_g1_arr := Chunk(hex.EncodeToString((&vk.G1.Alpha).Marshal()), 2)
	beta_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Beta).Marshal()), 4)
	gamma_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Gamma).Marshal()), 4)
	delta_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Delta).Marshal()), 4)
	CommitmentKey := hex.EncodeToString(comkey_writer.Bytes())

	vk_map := map[string]interface{}{
		"alpha_g1":      [2]string{alpha_g1_arr[0], alpha_g1_arr[1]},
		"beta_g2":       [2][2]string{{beta_g2_arr[1], beta_g2_arr[0]}, {beta_g2_arr[3], beta_g2_arr[2]}},
		"gamma_g2":      [2][2]string{{gamma_g2_arr[1], gamma_g2_arr[0]}, {gamma_g2_arr[3], gamma_g2_arr[2]}},
		"delta_g2":      [2][2]string{{delta_g2_arr[1], delta_g2_arr[0]}, {delta_g2_arr[3], delta_g2_arr[2]}},
		"gamma_abc_g1":  gamma_abc_g1_arr,
		"CommitmentKey": CommitmentKey,
		// "CommitmentKeyG": hex.EncodeToString((&vk.CommitmentKey.g).Marshal()),
		// "CommitmentKeyGRoot": hex.EncodeToString((&vk.CommitmentKey.gRootSigmaNeg).Marshal()),
		"PublicAndCommitmentCommitted": vk.PublicAndCommitmentCommitted,
	}

	return json.Marshal(vk_map)
}

func (gvk *G16VerifyingKey) UnmarshalJSON(data []byte) error {
	vk := gvk.VK.(*bls12381.VerifyingKey)
	var VerifyingKeyString struct {
		Alpha         [2]string    `json:"alpha_g1"`
		K             [][]string   `json:"gamma_abc_g1"`
		Beta          [2][2]string `json:"beta_g2"`
		Gamma         [2][2]string `json:"gamma_g2"`
		Delta         [2][2]string `json:"delta_g2"`
		CommitmentKey string       `json:"CommitmentKey"`
		// CommitmentKeyG string
		// CommitmentKeyGRoot string
		PublicAndCommitmentCommitted [][]int `json:"PublicAndCommitmentCommitted"`
	}

	err := json.Unmarshal(data, &VerifyingKeyString)
	if err != nil {
		return err
	}

	alpha_bytes, err := hex.DecodeString(VerifyingKeyString.Alpha[0] + VerifyingKeyString.Alpha[1])
	if err != nil {
		return err
	}
	err = vk.G1.Alpha.Unmarshal(alpha_bytes)
	if err != nil {
		return err
	}

	len := len(VerifyingKeyString.K)
	vk.G1.K = make([]curve.G1Affine, len)
	for i := 0; i < len; i++ {
		k_bytes, err := hex.DecodeString(VerifyingKeyString.K[i][0] + VerifyingKeyString.K[i][1])
		if err != nil {
			return err
		}
		err = vk.G1.K[i].Unmarshal(k_bytes)
		if err != nil {
			return err
		}
	}

	beta_bytes, err := hex.DecodeString(VerifyingKeyString.Beta[0][1] + VerifyingKeyString.Beta[0][0] + VerifyingKeyString.Beta[1][1] + VerifyingKeyString.Beta[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Beta.Unmarshal(beta_bytes)
	if err != nil {
		return err
	}

	gamma_bytes, err := hex.DecodeString(VerifyingKeyString.Gamma[0][1] + VerifyingKeyString.Gamma[0][0] + VerifyingKeyString.Gamma[1][1] + VerifyingKeyString.Gamma[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Gamma.Unmarshal(gamma_bytes)
	if err != nil {
		return err
	}

	delta_bytes, err := hex.DecodeString(VerifyingKeyString.Delta[0][1] + VerifyingKeyString.Delta[0][0] + VerifyingKeyString.Delta[1][1] + VerifyingKeyString.Delta[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Delta.Unmarshal(delta_bytes)
	if err != nil {
		return err
	}

	comkey_bytes, err := hex.DecodeString(VerifyingKeyString.CommitmentKey)
	if err != nil {
		return err
	}
	_, err = vk.CommitmentKey.ReadFrom(bytes.NewReader(comkey_bytes))
	if err != nil {
		return err
	}

	vk.PublicAndCommitmentCommitted = VerifyingKeyString.PublicAndCommitmentCommitted

	err = vk.Precompute()
	if err != nil {
		return err
	}

	return nil
}

func ReadCommonCircuitDataRaw(common_circuit_data_str string) (types.CommonCircuitData, error) {
	var raw types.CommonCircuitDataRaw
	var commonCircuitData types.CommonCircuitData
	if err := json.Unmarshal([]byte(common_circuit_data_str), &raw); err != nil {
		return commonCircuitData, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	commonCircuitData.Config.NumWires = raw.Config.NumWires
	commonCircuitData.Config.NumRoutedWires = raw.Config.NumRoutedWires
	commonCircuitData.Config.NumConstants = raw.Config.NumConstants
	commonCircuitData.Config.UseBaseArithmeticGate = raw.Config.UseBaseArithmeticGate
	commonCircuitData.Config.SecurityBits = raw.Config.SecurityBits
	commonCircuitData.Config.NumChallenges = raw.Config.NumChallenges
	commonCircuitData.Config.ZeroKnowledge = raw.Config.ZeroKnowledge
	commonCircuitData.Config.MaxQuotientDegreeFactor = raw.Config.MaxQuotientDegreeFactor

	commonCircuitData.Config.FriConfig.RateBits = raw.Config.FriConfig.RateBits
	commonCircuitData.Config.FriConfig.CapHeight = raw.Config.FriConfig.CapHeight
	commonCircuitData.Config.FriConfig.ProofOfWorkBits = raw.Config.FriConfig.ProofOfWorkBits
	commonCircuitData.Config.FriConfig.NumQueryRounds = raw.Config.FriConfig.NumQueryRounds

	commonCircuitData.FriParams.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.DegreeBits = raw.FriParams.DegreeBits
	commonCircuitData.FriParams.Config.RateBits = raw.FriParams.Config.RateBits
	commonCircuitData.FriParams.Config.CapHeight = raw.FriParams.Config.CapHeight
	commonCircuitData.FriParams.Config.ProofOfWorkBits = raw.FriParams.Config.ProofOfWorkBits
	commonCircuitData.FriParams.Config.NumQueryRounds = raw.FriParams.Config.NumQueryRounds
	commonCircuitData.FriParams.ReductionArityBits = raw.FriParams.ReductionArityBits

	commonCircuitData.GateIds = raw.Gates

	selectorGroupStart := []uint64{}
	selectorGroupEnd := []uint64{}
	for _, group := range raw.SelectorsInfo.Groups {
		selectorGroupStart = append(selectorGroupStart, group.Start)
		selectorGroupEnd = append(selectorGroupEnd, group.End)
	}

	commonCircuitData.SelectorsInfo = *gates.NewSelectorsInfo(
		raw.SelectorsInfo.SelectorIndices,
		selectorGroupStart,
		selectorGroupEnd,
	)

	commonCircuitData.QuotientDegreeFactor = raw.QuotientDegreeFactor
	commonCircuitData.NumGateConstraints = raw.NumGateConstraints
	commonCircuitData.NumConstants = raw.NumConstants
	commonCircuitData.NumPublicInputs = raw.NumPublicInputs
	commonCircuitData.KIs = raw.KIs
	commonCircuitData.NumPartialProducts = raw.NumPartialProducts

	// Don't support circuits that have hiding enabled
	if raw.FriParams.Hiding {
		return commonCircuitData, fmt.Errorf("Circuit has hiding enabled, which is not supported")
	}

	return commonCircuitData, nil
}

func ReadVerifierOnlyCircuitDataRaw(circuit_data_str string) (types.VerifierOnlyCircuitDataRaw, error) {
	var raw types.VerifierOnlyCircuitDataRaw
	if err := json.Unmarshal([]byte(circuit_data_str), &raw); err != nil {
		return raw, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	return raw, nil
}

func ReadProofWithPublicInputsRaw(proof_with_public_inputs_str string) (types.ProofWithPublicInputsRaw, error) {

	var raw types.ProofWithPublicInputsRaw
	if err := json.Unmarshal([]byte(proof_with_public_inputs_str), &raw); err != nil {
		return raw, fmt.Errorf("Failed to unmarshal proof with public inputs: %v", err)
	}

	return raw, nil
}
