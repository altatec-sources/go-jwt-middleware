package jwt

// IssuerConfig describes JWT validation parameters for a single issuer.
type IssuerConfig struct {
	PublicKey string
	Issuer    string
	Audience  string
}
