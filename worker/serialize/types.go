package serialize

type ArkProofE2 struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}
type ArkProofG1 struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type ArkProofG2 struct {
	X ArkProofE2 `json:"x"`
	Y ArkProofE2 `json:"y"`
}
type ArkVK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkProofG1 `json:"k"`
}
type ArkProof struct {
	Ar      ArkProofG1 `json:"pi_a"`
	Bs      ArkProofG2 `json:"pi_b"`
	Krs     ArkProofG1 `json:"pi_c"`
	Witness []string   `json:"public_inputs"`
}

type ArkHex2Proof struct {
	Ar      ArkProofG1 `json:"pi_a"`
	Bs      ArkProofG2 `json:"pi_b"`
	Krs     ArkProofG1 `json:"pi_c"`
	Witness []string   `json:"public_inputs"`
}

type ArkHexProof struct {
	Ar      string   `json:"pi_a"`
	Bs      string   `json:"pi_b"`
	Krs     string   `json:"pi_c"`
	Witness []string `json:"public_inputs"`
}

type ArkHex2VK struct {
	AlphaG1 ArkProofG1 `json:"alpha_g1"`
	BetaG2  ArkProofG2 `json:"beta_g2"`
	GammaG2 ArkProofG2 `json:"gamma_g2"`
	DeltaG2 ArkProofG2 `json:"delta_g2"`
	// length dependent on circuit public inputs
	G1K []ArkProofG1 `json:"k"`
}
