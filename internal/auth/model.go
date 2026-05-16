package auth

type User struct {
	RandomUUID        string
	UsernameEncrypted string
	PublicKey         string
	EncryptedBlob     string
	Salt1             string
	AuthHash          string
	Salt2             string
	TokenVersion      int
}

type RegisterRequest struct {
	Username      string `json:"username"`
	PublicKey     string `json:"public_key"`
	EncryptedBlob string `json:"blob"`
	Salt1         string `json:"salt1"`
	AuthHash      string `json:"auth_hash"`
	Salt2         string `json:"salt2"`
}
