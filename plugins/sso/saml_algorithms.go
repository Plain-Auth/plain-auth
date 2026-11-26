package sso

// SignatureAlgorithm is an XML Signature method URI (RFC 6931) for SAML
// messages.
type SignatureAlgorithm string

// The XML Signature methods. RSA-SHA1 is deprecated and always refused.
const (
	SignatureRSASHA1     SignatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureRSASHA256   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA384   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureRSASHA512   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureECDSASHA256 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignatureECDSASHA384 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureECDSASHA512 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// DigestAlgorithm is an XML Signature digest method URI.
type DigestAlgorithm string

// The XML Signature digests. SHA-1 is deprecated and always refused.
const (
	DigestSHA1   DigestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 DigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 DigestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 DigestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// KeyEncryptionAlgorithm is an XML Encryption key transport URI. This service
// decrypts only KeyEncryptionRSAOAEPSHA256, with SHA-256 digest and
// MGF1-SHA256 parameters.
type KeyEncryptionAlgorithm string

// The XML Encryption key transports. RSA 1.5 is deprecated.
const (
	KeyEncryptionRSA15         KeyEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	KeyEncryptionRSAOAEP       KeyEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncryptionRSAOAEPSHA256 KeyEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// DataEncryptionAlgorithm is an XML Encryption content cipher URI. This
// service decrypts only DataEncryptionAES256GCM.
type DataEncryptionAlgorithm string

// The XML Encryption content ciphers. Triple DES is deprecated.
const (
	DataEncryptionTripleDESCBC DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	DataEncryptionAES128CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataEncryptionAES192CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	DataEncryptionAES256CBC    DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	DataEncryptionAES128GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataEncryptionAES192GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	DataEncryptionAES256GCM    DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)
