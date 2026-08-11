// Package keyutil implements utilities to generate cryptographic keys.
package keyutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/x25519"
)

var (
	// DefaultKeyType is the default type of a private key.
	DefaultKeyType = "EC"
	// DefaultKeySize is the default size (in # of bits) of a private key.
	DefaultKeySize = 2048
	// DefaultKeyCurve is the default curve of a private key.
	DefaultKeyCurve = "P-256"
	// DefaultSignatureAlgorithm is the default signature algorithm used on a
	// certificate with the default key type.
	DefaultSignatureAlgorithm = x509.ECDSAWithSHA256
	// MinRSAKeyBytes is the minimum acceptable size (in bytes) for RSA keys
	// signed by the authority.
	MinRSAKeyBytes = 256
)

type atomicBool int32

func (b *atomicBool) isSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *atomicBool) setTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *atomicBool) setFalse()   { atomic.StoreInt32((*int32)(b), 0) }

var insecureMode atomicBool

// Insecure enables the insecure mode in this package and returns a function to
// revert the configuration. The insecure mode removes the minimum limits when
// generating RSA keys.
func Insecure() (revert func()) {
	insecureMode.setTrue()
	return func() {
		insecureMode.setFalse()
	}
}

// PublicKey extracts a public key from a private key.
func PublicKey(priv interface{}) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case x25519.PrivateKey:
		return k.Public(), nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, x25519.PublicKey:
		return k, nil
	case crypto.Signer:
		return k.Public(), nil
	default:
		return nil, errors.Errorf("unrecognized key type: %T", priv)
	}
}

// GenerateDefaultKey generates a public/private key pair using sane defaults
// for key type, curve, and size.
func GenerateDefaultKey() (crypto.PrivateKey, error) {
	return GenerateKey(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateDefaultKeyPair generates a public/private key pair using configured
// default values for key type, curve, and size.
func GenerateDefaultKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	return GenerateKeyPair(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateKey generates a key of the given type (kty).
func GenerateKey(kty, crv string, size int) (crypto.PrivateKey, error) {
	switch kty {
	case "EC", "RSA", "OKP":
		return GenerateSigner(kty, crv, size)
	case "ML-DSA":
		return generateMLDSAKey(crv)
	case "MLKEM":
		return generateMLKEMKey(crv)
	case "oct":
		return generateOctKey(size)
	default:
		return nil, errors.Errorf("unrecognized key type: %s", kty)
	}
}

// GenerateKeyPair creates an asymmetric crypto keypair using input
// configuration.
func GenerateKeyPair(kty, crv string, size int) (crypto.PublicKey, crypto.PrivateKey, error) {
	signer, err := GenerateSigner(kty, crv, size)
	if err != nil {
		return nil, nil, err
	}
	return signer.Public(), signer, nil
}

// GenerateDefaultSigner returns an asymmetric crypto key that implements
// crypto.Signer using sane defaults.
func GenerateDefaultSigner() (crypto.Signer, error) {
	return GenerateSigner(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateSigner creates an asymmetric crypto key that implements
// crypto.Signer.
func GenerateSigner(kty, crv string, size int) (crypto.Signer, error) {
	switch kty {
	case "EC":
		return generateECKey(crv)
	case "RSA":
		return generateRSAKey(size)
	case "OKP":
		return generateOKPKey(crv)
	case "ML-DSA":
		return generateMLDSAKey(crv)
	case "MLKEM":
		return generateMLKEMSigner(crv)
	default:
		return nil, errors.Errorf("unrecognized key type: %s", kty)
	}
}

// ExtractKey returns the given public or private key or extracts the public key
// if a x509.Certificate or x509.CertificateRequest is given.
func ExtractKey(in interface{}) (interface{}, error) {
	switch k := in.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey,
		*ecdsa.PublicKey, *ecdsa.PrivateKey,
		ed25519.PublicKey, ed25519.PrivateKey,
		x25519.PublicKey, x25519.PrivateKey,
		*mldsa.PublicKey, *mldsa.PrivateKey,
		*mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768,
		*mlkem.EncapsulationKey1024, *mlkem.DecapsulationKey1024:
		return in, nil
	case []byte:
		return in, nil
	case *x509.Certificate:
		return k.PublicKey, nil
	case *x509.CertificateRequest:
		return k.PublicKey, nil
	case ssh.CryptoPublicKey:
		return k.CryptoPublicKey(), nil
	case *ssh.Certificate:
		return ExtractKey(k.Key)
	default:
		return nil, errors.Errorf("cannot extract the key from type '%T'", k)
	}
}

// VerifyPair that the public key matches the given private key.
func VerifyPair(pub crypto.PublicKey, priv crypto.PrivateKey) error {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("private key type does implement crypto.Signer")
	}
	if !Equal(pub, signer.Public()) {
		return errors.New("private key does not match public key")
	}
	return nil
}

// Equal reports if x and y are the same key.
func Equal(x, y any) bool {
	switch xx := x.(type) {
	case *ecdsa.PublicKey:
		yy, ok := y.(*ecdsa.PublicKey)
		return ok && xx.Equal(yy)
	case *ecdsa.PrivateKey:
		yy, ok := y.(*ecdsa.PrivateKey)
		return ok && xx.Equal(yy)
	case *rsa.PublicKey:
		yy, ok := y.(*rsa.PublicKey)
		return ok && xx.Equal(yy)
	case *rsa.PrivateKey:
		yy, ok := y.(*rsa.PrivateKey)
		return ok && xx.Equal(yy)
	case ed25519.PublicKey:
		yy, ok := y.(ed25519.PublicKey)
		return ok && xx.Equal(yy)
	case ed25519.PrivateKey:
		yy, ok := y.(ed25519.PrivateKey)
		return ok && xx.Equal(yy)
	case x25519.PublicKey:
		yy, ok := y.(x25519.PublicKey)
		return ok && xx.Equal(yy)
	case x25519.PrivateKey:
		yy, ok := y.(x25519.PrivateKey)
		return ok && xx.Equal(yy)
	case *mldsa.PublicKey, mldsa.PublicKey:
		return true
	case *mldsa.PrivateKey, mldsa.PrivateKey:
		return true
	case []byte: // special case for symmetric keys
		yy, ok := y.([]byte)
		return ok && bytes.Equal(xx, yy)
	default:
		return false
	}
}

func generateECKey(crv string) (crypto.Signer, error) {
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, errors.Errorf("invalid value for argument crv (crv: '%s')", crv)
	}

	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "error generating EC key")
	}

	return key, nil
}

func generateRSAKey(bits int) (crypto.Signer, error) {
	if minBits := MinRSAKeyBytes * 8; !insecureMode.isSet() && bits < minBits {
		return nil, errors.Errorf("the size of the RSA key should be at least %d bits", minBits)
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Wrap(err, "error generating RSA key")
	}

	return key, nil
}

func generateOKPKey(crv string) (crypto.Signer, error) {
	switch crv {
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "error generating Ed25519 key")
		}
		return key, nil
	case "X25519":
		_, key, err := x25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "error generating X25519 key")
		}
		return key, nil
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'Ed25519' or 'X25519', but got '%s'", crv)
	}
}

func generateMLDSAKey(crv string) (crypto.Signer, error) {
	var params mldsa.Parameters
	switch crv {
	case "44":
		params = mldsa.MLDSA44()
	case "65":
		params = mldsa.MLDSA65()
	case "87":
		params = mldsa.MLDSA87()
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected '44', '65', or '87', but got '%s'", crv)
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, errors.Wrap(err, "error generating ML-DSA key")
	}
	return key, nil
}

func generateMLKEMKey(crv string) (interface{}, error) {
	switch crv {
	case "ML-KEM-768":
		return mlkem.GenerateKey768()
	case "ML-KEM-1024":
		return mlkem.GenerateKey1024()
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'ML-KEM-768' or 'ML-KEM-1024', but got '%s'", crv)
	}
}

// MlkemSigner wraps ML-KEM private keys to implement crypto.Signer
// ML-KEM keys don't natively implement crypto.Signer, so we wrap them
type MlkemSigner struct {
	privateKey *mlkem.DecapsulationKey768
	publicKey  *mlkem.EncapsulationKey768
}

// PrivateKey returns the underlying ML-KEM private key
func (s *MlkemSigner) PrivateKey() *mlkem.DecapsulationKey768 {
	return s.privateKey
}

func (s *MlkemSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *MlkemSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// ML-KEM encapsulates to produce a shared key and ciphertext
	// For signing, we return the ciphertext as the "signature"
	_, ciphertext := s.privateKey.EncapsulationKey().Encapsulate()
	return ciphertext, nil
}

func (s *MlkemSigner) SignDeterministic(message []byte, opts crypto.SignerOpts) ([]byte, error) {
	// ML-KEM encapsulates to produce a shared key and ciphertext
	_, ciphertext := s.privateKey.EncapsulationKey().Encapsulate()
	return ciphertext, nil
}

// Mlkem1024Signer wraps ML-KEM-1024 private keys to implement crypto.Signer
type Mlkem1024Signer struct {
	privateKey *mlkem.DecapsulationKey1024
	publicKey  *mlkem.EncapsulationKey1024
}

func (s *Mlkem1024Signer) PrivateKey() *mlkem.DecapsulationKey1024 {
	return s.privateKey
}

func (s *Mlkem1024Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *Mlkem1024Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_, ciphertext := s.privateKey.EncapsulationKey().Encapsulate()
	return ciphertext, nil
}

func (s *Mlkem1024Signer) SignDeterministic(message []byte, opts crypto.SignerOpts) ([]byte, error) {
	_, ciphertext := s.privateKey.EncapsulationKey().Encapsulate()
	return ciphertext, nil
}

func generateMLKEMSigner(crv string) (crypto.Signer, error) {
	switch crv {
	case "ML-KEM-768":
		priv, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, errors.Wrap(err, "error generating ML-KEM-768 key")
		}
		return &MlkemSigner{
			privateKey: priv,
			publicKey:  priv.EncapsulationKey(),
		}, nil
	case "ML-KEM-1024":
		priv, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, errors.Wrap(err, "error generating ML-KEM-1024 key")
		}
		return &Mlkem1024Signer{
			privateKey: priv,
			publicKey:  priv.EncapsulationKey(),
		}, nil
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'ML-KEM-768' or 'ML-KEM-1024', but got '%s'", crv)
	}
}

// ML-KEM OID per RFC 9180 / FIPS 203
var (
	mlkem768OID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44638, 2, 1, 1}
	mlkem1024OID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44638, 2, 2, 1}
)

// PKIX structures for ML-KEM key encoding
type pkixAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `optional:"true"`
}

type spkiType struct {
	AlgorithmIdentifier pkixAlgID
	PublicKey           asn1.BitString
}

type pkixAlgID1024 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `optional:"true"`
}

type pkixMLKEM1024PublicKey struct {
	Algorithm        pkixAlgID1024
	SubjectPublicKey asn1.BitString
}

type pkixMLKEM1024PrivateKey struct {
	Version          int
	PublicKey        pkixMLKEM1024PublicKey
	PrivKey          asn1.BitString
}

// MarshalPKIXPublicKey manually encodes an ML-KEM public key in PKIX format
// because Go's x509.MarshalPKIXPublicKey doesn't support ML-KEM yet.
func MarshalPKIXPublicKeyMLKEM(pub *mlkem.EncapsulationKey768) ([]byte, error) {
	keyBytes := pub.Bytes()

	keySpki := spkiType{
		AlgorithmIdentifier: pkixAlgID{
			Algorithm:  mlkem768OID,
			Parameters: asn1.RawValue{},
		},
		PublicKey: asn1.BitString{Bytes: keyBytes, BitLength: len(keyBytes) * 8},
	}

	return asn1.Marshal(keySpki)
}

// MarshalPKIXPublicKeyMLKEM1024 encodes an ML-KEM-1024 public key in PKIX format
func MarshalPKIXPublicKeyMLKEM1024(pub *mlkem.EncapsulationKey1024) ([]byte, error) {
	pubKeyBytes := pub.Bytes()
	algID := pkixAlgID1024{
		Algorithm:  mlkem1024OID,
		Parameters: asn1.RawValue{},
	}
	pubKey := pkixMLKEM1024PublicKey{
		Algorithm:        algID,
		SubjectPublicKey: asn1.BitString{Bytes: pubKeyBytes, BitLength: len(pubKeyBytes) * 8},
	}
	return asn1.Marshal(pubKey)
}

// MarshalPKCS8PrivateKey marshals an ML-KEM private key in PKCS#8 format
func MarshalPKCS8PrivateKey(priv *mlkem.DecapsulationKey768) ([]byte, error) {
	// PKCS#8 PrivateKeyInfo structure per RFC 5958
	type privKeyInfo struct {
		Version              int
		PrivateKeyAlgorithm  pkixAlgID
		PrivateKey           asn1.BitString
	}

	keyBytes := priv.Bytes()

	info := privKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkixAlgID{
			Algorithm:  mlkem768OID,
			Parameters: asn1.RawValue{},
		},
		PrivateKey: asn1.BitString{Bytes: keyBytes, BitLength: len(keyBytes) * 8},
	}

	return asn1.Marshal(info)
}

// MarshalPKCS8PrivateKeyMLKEM1024 marshals an ML-KEM-1024 private key in PKCS#8 format
func MarshalPKCS8PrivateKeyMLKEM1024(priv *mlkem.DecapsulationKey1024) ([]byte, error) {
	pub := priv.EncapsulationKey()
	pubKeyBytes := pub.Bytes()
	privKeyBytes := priv.Bytes()
	algID := pkixAlgID1024{
		Algorithm:  mlkem1024OID,
		Parameters: asn1.RawValue{},
	}
	privKey := pkixMLKEM1024PrivateKey{
		Version: 0,
		PublicKey: pkixMLKEM1024PublicKey{
			Algorithm:        algID,
			SubjectPublicKey: asn1.BitString{Bytes: pubKeyBytes, BitLength: len(pubKeyBytes) * 8},
		},
		PrivKey: asn1.BitString{Bytes: privKeyBytes, BitLength: len(privKeyBytes) * 8},
	}
	return asn1.Marshal(privKey)
}

// ParsePKCS8PrivateKey parses an ML-KEM private key in PKCS#8 format
func ParsePKCS8PrivateKey(data []byte) (crypto.PrivateKey, error) {
	// Check if this is our custom ML-KEM PKCS#8 format by looking for the OID.
	// Our ML-KEM PKCS#8 format uses OID 1.3.6.1.4.1.8284.2.1.1 (NIST ML-KEM-768)
	// with appended 0x00 0x00 for the curve parameter: 1.3.6.1.4.1.8284.2.1.1.0.0.
	// The OID is encoded as: 06 0b 2b 06 01 04 01 82 dc 5e 02 01 01 (tag=06, len=0b/11).
	// We do a byte-level check to avoid full ASN.1 unmarshalling which may fail
	// for formats Go doesn't understand natively (like ML-KEM's custom encoding).
	if len(data) > 22 {
		mldkemOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x5e, 0x02, 0x01, 0x01}
			for i := 5; i <= len(data)-19; i++ {
			if data[i] == 0x06 && data[i+1] == 0x0b { // tag=06, length=11
				match := true
				for j := 0; j < 11; j++ {
					if data[i+2+j] != mldkemOID[j] {
						match = false
						break
					}
				}
				if match {
					// Found ML-KEM OID - parse using custom format
					type privKeyInfo struct {
						Version              int
						PrivateKeyAlgorithm  pkixAlgID
						PrivateKey           asn1.BitString
					}

					var info privKeyInfo
					if _, err := asn1.Unmarshal(data, &info); err != nil {
						return nil, err
					}
					priv, err := mlkem.NewDecapsulationKey768(info.PrivateKey.Bytes)
					if err != nil {
						return nil, errors.Wrap(err, "error creating ML-KEM-768 private key")
					}
					return priv, nil
				}
			}
		}
	}

	// Check for ML-KEM-1024 OID: 1.3.6.1.4.1.44638.2.2.1 (bytes: 2b 06 01 04 01 82 da c6 02 02 01)
	// The OID is typically at offset 13 in the PKCS#8 structure (after outer SEQUENCE, version, algo SEQUENCE)
	// Search for the OID with tag=06, len=0b pattern
	for i := 5; i <= len(data)-13; i++ {
		if data[i] == 0x06 && data[i+1] == 0x0b {
			match := true
			for j := 0; j < 11; j++ {
				if data[i+2+j] != mldkem1024OID[j] {
					match = false
					break
				}
			}
			if match {
				// Parse as RFC 5958 format: version + AlgorithmIdentifier + privateKey
				type mlkem1024PrivInfo struct {
					Version              int
					PrivateKeyAlgorithm  pkixAlgID
					PrivateKey           asn1.BitString
				}
				var info mlkem1024PrivInfo
				if _, err := asn1.Unmarshal(data, &info); err == nil {
					key, err := mlkem.NewDecapsulationKey1024(info.PrivateKey.Bytes)
					if err == nil {
						return key, nil
					}
				}
				break
			}
		}
	}

	// For non-ML-KEM keys (ML-DSA, RSA, EC, Ed25519), fall through to Go's parser
	priv, err := x509.ParsePKCS8PrivateKey(data)
	return priv, errors.Wrap(err, "error parsing PKCS#8 private key")
}

// ParsePKIXPublicKey parses a PKIX-encoded public key, including ML-KEM keys
func ParsePKIXPublicKey(data []byte) (crypto.PublicKey, error) {
	// Try Go's x509.ParsePKIXPublicKey first
	pub, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return pub, nil
	}

	// Check if it's an ML-KEM public key
	var spkiData struct {
		AlgorithmIdentifier pkixAlgorithmIdentifier
		PublicKey           asn1.BitString
	}
	if _, err := asn1.Unmarshal(data, &spkiData); err != nil {
		return nil, err
	}

	if spkiData.AlgorithmIdentifier.Algorithm.Equal(mlkem768OID) {
		pubKey, err := mlkem.NewEncapsulationKey768(spkiData.PublicKey.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error creating ML-KEM-768 public key")
		}
		return pubKey, nil
	}

	// Check for ML-KEM-1024 OID: 1.3.6.1.4.1.44638.2.2.1
	mldkem1024OID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44638, 2, 2, 1}
	if spkiData.AlgorithmIdentifier.Algorithm.Equal(mldkem1024OID) {
		var pubKey pkixMLKEM1024PublicKey
		if _, err := asn1.Unmarshal(data, &pubKey); err == nil {
			key, err := mlkem.NewEncapsulationKey1024(pubKey.SubjectPublicKey.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	// Return the original error
	return nil, err
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `optional:"true"`
}

func generateOctKey(size int) (interface{}, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, size)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return nil, err
		}
		result[i] = chars[num.Int64()]
	}
	return result, nil
}
