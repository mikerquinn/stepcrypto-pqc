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

// GenerateKeyPair creates an asymmetric crypto keypair using input configuration.
func GenerateKeyPair(kty, crv string, size int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch kty {
	case "MLKEM":
		return generateMLKEMKeyPair(kty, crv)
	default:
		signer, err := GenerateSigner(kty, crv, size)
		if err != nil {
			return nil, nil, err
		}
		return signer.Public(), signer, nil
	}
}

// generateMLKEMKeyPair returns a non-signer ML-KEM key pair
func generateMLKEMKeyPair(kty, crv string) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch crv {
	case "ML-KEM-768":
		return generateMLKEMKeyPair768()
	case "ML-KEM-1024":
		return generateMLKEMKeyPair1024()
	default:
		return nil, nil, errors.Errorf("unsupported ML-KEM curve: %s", crv)
	}
}

func generateMLKEMKeyPair768() (*mlkem.EncapsulationKey768, *MlkemKeyPair, error) {
	priv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating ML-KEM-768 key")
	}
	return priv.EncapsulationKey(), &MlkemKeyPair{
		DecapsulationKey: priv,
		EncapsulationKey: priv.EncapsulationKey(),
	}, nil
}

func generateMLKEMKeyPair1024() (*mlkem.EncapsulationKey1024, *Mlkem1024KeyPair, error) {
	priv, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating ML-KEM-1024 key")
	}
	return priv.EncapsulationKey(), &Mlkem1024KeyPair{
		DecapsulationKey: priv,
		EncapsulationKey: priv.EncapsulationKey(),
	}, nil
}

// GenerateDefaultSigner returns an asymmetric crypto key that implements
// crypto.Signer using sane defaults.
func GenerateDefaultSigner() (crypto.Signer, error) {
	return GenerateSigner(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateSigner creates an asymmetric crypto key that implements
// crypto.Signer. ML-KEM keys cannot sign (they are KEM keys only).
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
		return nil, errors.Errorf("ML-KEM keys cannot be used to sign; use ML-DSA or a classical algorithm")
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
// For ML-KEM keys, it checks that the encapsulation key matches.
func VerifyPair(pub crypto.PublicKey, priv crypto.PrivateKey) error {
	// Handle ML-KEM key pairs
	switch kp := priv.(type) {
	case *MlkemKeyPair:
		yy, ok := pub.(*mlkem.EncapsulationKey768)
		if !ok {
			return errors.New("public key type does not match private key")
		}
		if !Equal(kp.EncapsulationKey, yy) {
			return errors.New("private key does not match public key")
		}
		return nil
	case *Mlkem1024KeyPair:
		yy, ok := pub.(*mlkem.EncapsulationKey1024)
		if !ok {
			return errors.New("public key type does not match private key")
		}
		if !Equal(kp.EncapsulationKey, yy) {
			return errors.New("private key does not match public key")
		}
		return nil
	}
	// For all other key types, use crypto.Signer interface
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("private key type does not implement crypto.Signer")
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
	case *mldsa.PublicKey:
		yy, ok := y.(*mldsa.PublicKey)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case mldsa.PublicKey:
		yy, ok := y.(mldsa.PublicKey)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *mldsa.PrivateKey:
		yy, ok := y.(*mldsa.PrivateKey)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case mldsa.PrivateKey:
		yy, ok := y.(mldsa.PrivateKey)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *mlkem.EncapsulationKey768:
		yy, ok := y.(*mlkem.EncapsulationKey768)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *mlkem.DecapsulationKey768:
		yy, ok := y.(*mlkem.DecapsulationKey768)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *mlkem.EncapsulationKey1024:
		yy, ok := y.(*mlkem.EncapsulationKey1024)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *mlkem.DecapsulationKey1024:
		yy, ok := y.(*mlkem.DecapsulationKey1024)
		return ok && bytes.Equal(xx.Bytes(), yy.Bytes())
	case *MlkemKeyPair:
		yy, ok := y.(*MlkemKeyPair)
		return ok && bytes.Equal(xx.EncapsulationKey.Bytes(), yy.EncapsulationKey.Bytes()) &&
			bytes.Equal(xx.DecapsulationKey.Bytes(), yy.DecapsulationKey.Bytes())
	case *Mlkem1024KeyPair:
		yy, ok := y.(*Mlkem1024KeyPair)
		return ok && bytes.Equal(xx.EncapsulationKey.Bytes(), yy.EncapsulationKey.Bytes()) &&
			bytes.Equal(xx.DecapsulationKey.Bytes(), yy.DecapsulationKey.Bytes())
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
		priv, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, errors.Wrap(err, "error generating ML-KEM-768 key")
		}
		return &MlkemKeyPair{
			DecapsulationKey: priv,
			EncapsulationKey: priv.EncapsulationKey(),
		}, nil
	case "ML-KEM-1024":
		priv, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, errors.Wrap(err, "error generating ML-KEM-1024 key")
		}
		return &Mlkem1024KeyPair{
			DecapsulationKey: priv,
			EncapsulationKey: priv.EncapsulationKey(),
		}, nil
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'ML-KEM-768' or 'ML-KEM-1024', but got '%s'", crv)
	}
}

// MlkemKeyPair wraps an ML-KEM-768 key pair
type MlkemKeyPair struct {
	EncapsulationKey *mlkem.EncapsulationKey768
	DecapsulationKey *mlkem.DecapsulationKey768
}

func (p *MlkemKeyPair) Public() crypto.PublicKey {
	return p.EncapsulationKey
}

func (p *MlkemKeyPair) Private() interface{} {
	return p.DecapsulationKey
}

// Mlkem1024KeyPair wraps an ML-KEM-1024 key pair
type Mlkem1024KeyPair struct {
	EncapsulationKey *mlkem.EncapsulationKey1024
	DecapsulationKey *mlkem.DecapsulationKey1024
}

func (p *Mlkem1024KeyPair) Public() crypto.PublicKey {
	return p.EncapsulationKey
}

func (p *Mlkem1024KeyPair) Private() interface{} {
	return p.DecapsulationKey
}

// GenerateMLKEMKeyPair returns an ML-KEM key pair (not a crypto.Signer)
func GenerateMLKEMKeyPair(crv string) (*MlkemKeyPair, error) {
	priv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, errors.Wrap(err, "error generating ML-KEM-768 key")
	}
	return &MlkemKeyPair{
		DecapsulationKey: priv,
		EncapsulationKey: priv.EncapsulationKey(),
	}, nil
}

// GenerateMLKEM1024KeyPair returns an ML-KEM-1024 key pair (not a crypto.Signer)
func GenerateMLKEM1024KeyPair(crv string) (*Mlkem1024KeyPair, error) {
	priv, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, errors.Wrap(err, "error generating ML-KEM-1024 key")
	}
	return &Mlkem1024KeyPair{
		DecapsulationKey: priv,
		EncapsulationKey: priv.EncapsulationKey(),
	}, nil
}

// ML-KEM OIDs per FIPS 203 / RFC 9448.
// 2.16.840.1.101.3.4.4 is the NIST ML-KEM OID tree.
//
//	id-ML-KEM-768 (2.16.840.1.101.3.4.4.2)  – FIPS 203 level 3
//	id-ML-KEM-1024 (2.16.840.1.101.3.4.4.3) – FIPS 203 level 4
var (
	mlkem768OID   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	mlkem1024OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
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

// MarshalPKCS8PrivateKey marshals an ML-KEM-768 private key in PKCS#8 format.
// The structure matches ML-KEM-1024: public key inside AlgorithmIdentifier,
// private key at outer level.
func MarshalPKCS8PrivateKey(priv *mlkem.DecapsulationKey768) ([]byte, error) {
	pub := priv.EncapsulationKey()
	pubKeyBytes := pub.Bytes()
	privKeyBytes := priv.Bytes()

	privKey := mlkemPKCS8PrivateKey{
		Version: 0,
		AlgorithmIdentifier: struct {
			Algorithm  struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue
			}
			PrivateKey asn1.BitString
		}{
			Algorithm: struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue
			}{
				Algorithm:  mlkem768OID,
				Parameters: asn1.RawValue{Tag: 5}, // NULL
			},
			PrivateKey: asn1.BitString{Bytes: pubKeyBytes, BitLength: len(pubKeyBytes) * 8},
		},
	}
	privKey.PublicKey = asn1.BitString{Bytes: privKeyBytes, BitLength: len(privKeyBytes) * 8}
	return asn1.Marshal(privKey)
}

// MarshalPKCS8PrivateKeyMLKEM1024 marshals an ML-KEM-1024 private key in PKCS#8 format.
// The structure is:
//
//	SEQUENCE { version, AlgorithmIdentifier { Algorithm, publicKey }, privateKey }
func MarshalPKCS8PrivateKeyMLKEM1024(priv *mlkem.DecapsulationKey1024) ([]byte, error) {
	pub := priv.EncapsulationKey()
	pubKeyBytes := pub.Bytes()
	privKeyBytes := priv.Bytes()

	// Use the same structure as ParsePKCS8PrivateKey expects
	privKey := mlkemPKCS8PrivateKey{
		Version: 0,
		AlgorithmIdentifier: struct {
			Algorithm  struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue
			}
			PrivateKey asn1.BitString
		}{
			Algorithm: struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue
			}{
				Algorithm:  mlkem1024OID,
				Parameters: asn1.RawValue{Tag: 5}, // NULL
			},
			// The BIT STRING inside AlgorithmIdentifier is the encapsulation (public) key
			PrivateKey: asn1.BitString{Bytes: pubKeyBytes, BitLength: len(pubKeyBytes) * 8},
		},
	}
	// Add the decapsulation (private) key at the outer level
	privKey.PublicKey = asn1.BitString{Bytes: privKeyBytes, BitLength: len(privKeyBytes) * 8}
	return asn1.Marshal(privKey)
}

// ParsePKCS8PrivateKey parses an ML-KEM private key in PKCS#8 format.
// ML-KEM PKCS#8 format per NIST FIPS 203 (RFC 9180):
//
//	PrivateKeyInfo ::= SEQUENCE {
//	    version                   INTEGER,
//	    privateKeyAlgorithm       AlgorithmIdentifier,
//	    privateKey                BIT STRING,
//	    publicKey                 [0] BIT STRING OPTIONAL
//	}
//
// The AlgorithmIdentifier contains the OID and parameters.
func ParsePKCS8PrivateKey(data []byte) (crypto.PrivateKey, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// ML-KEM-768 OID: 2.16.840.1.101.3.4.4.2 = 2b 06 01 04 01 a2 77 0d 03 04 02
	// ML-KEM-1024 OID: 2.16.840.1.101.3.4.4.3 = 2b 06 01 04 01 a2 77 0d 03 04 03
	// NIST ML-KEM OID tree 2.16.840.1.101.3.4.4
	var detectedCurve string

	// Search for ML-KEM OID in the data
	for i := 5; i <= len(data)-13; i++ {
		if data[i] == 0x06 && data[i+1] == 0x0b { // tag=06, length=11
			// Check for ML-KEM-1024 OID first (more specific)
			mldkem1024OID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xa2, 0x77, 0x0d, 0x03, 0x04, 0x03}
			match := true
			for j := 0; j < 11; j++ {
				if data[i+2+j] != mldkem1024OID[j] {
					match = false
					break
				}
			}
			if match {
				detectedCurve = "ML-KEM-1024"
				break
			}

			// Check for ML-KEM-768 OID
			mldkem768OID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xa2, 0x77, 0x0d, 0x03, 0x04, 0x02}
			match = true
			for j := 0; j < 11; j++ {
				if data[i+2+j] != mldkem768OID[j] {
					match = false
					break
				}
			}
			if match {
				detectedCurve = "ML-KEM-768"
				break
			}
		}
	}

	switch detectedCurve {
	case "ML-KEM-1024":
		return parseMLKEM1024PrivateKey(data)
	case "ML-KEM-768":
		return parseMLKEM768PrivateKey(data)
	}

	// For non-ML-KEM keys (ML-DSA, RSA, EC, Ed25519), fall through to Go's parser
	priv, err := x509.ParsePKCS8PrivateKey(data)
	return priv, errors.Wrap(err, "error parsing PKCS#8 private key")
}

// ML-KEM PKCS#8 structure:
//
//	SEQUENCE {
//	    version                   INTEGER (0),
//	    privateKeyAlgorithm       AlgorithmIdentifier,
//	    privateKey                BIT STRING,
//	    publicKey                 [0] BIT STRING OPTIONAL
//	}
//
// Where AlgorithmIdentifier is:
//	SEQUENCE { Algorithm SEQUENCE { OID, NULL }, privateKey BIT STRING }
type mlkemPKCS8PrivateKey struct {
	Version           int
	AlgorithmIdentifier struct {
		Algorithm  struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		PrivateKey asn1.BitString
	}
	PublicKey asn1.BitString `asn1:"optional,explicit,tag:0"`
}

func parseMLKEM768PrivateKey(data []byte) (crypto.PrivateKey, error) {
	var info mlkemPKCS8PrivateKey
	if _, err := asn1.Unmarshal(data, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling ML-KEM-768 PKCS#8 private key")
	}
	// The AlgorithmIdentifier.PrivateKey contains the encapsulation (public) key
	// The outer PublicKey field contains the decapsulation (private) key
	priv, err := mlkem.NewDecapsulationKey768(info.PublicKey.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating ML-KEM-768 private key")
	}
	return priv, nil
}

func parseMLKEM1024PrivateKey(data []byte) (crypto.PrivateKey, error) {
	var info mlkemPKCS8PrivateKey
	if _, err := asn1.Unmarshal(data, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling ML-KEM-1024 PKCS#8 private key")
	}
	// The AlgorithmIdentifier.PrivateKey contains the encapsulation (public) key
	// The outer PublicKey field contains the decapsulation (private) key
	priv, err := mlkem.NewDecapsulationKey1024(info.PublicKey.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating ML-KEM-1024 private key")
	}
	return priv, nil
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

	// Check for ML-KEM-1024 OID: 2.16.840.1.101.3.4.4.3
	if spkiData.AlgorithmIdentifier.Algorithm.Equal(mlkem1024OID) {
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
