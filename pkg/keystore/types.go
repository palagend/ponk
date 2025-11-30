// Package keystore provides secure key management functionality for multiple blockchain platforms
package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// Algorithm defines the interface for different cryptographic algorithms
type Algorithm interface {
	// Name returns the name of the algorithm
	Name() string

	// GenerateKeyPair generates a new key pair
	GenerateKeyPair() (interface{}, interface{}, error)

	// PrivateKeyToBytes converts a private key to bytes
	PrivateKeyToBytes(privateKey interface{}) ([]byte, error)

	// PublicKeyToBytes converts a public key to bytes
	PublicKeyToBytes(publicKey interface{}) ([]byte, error)

	// BytesToPrivateKey converts bytes to a private key
	BytesToPrivateKey(data []byte) (interface{}, error)

	// BytesToPublicKey converts bytes to a public key
	BytesToPublicKey(data []byte) (interface{}, error)

	// Sign signs a hash with the private key
	Sign(privateKey interface{}, hash []byte) ([]byte, error)

	// Verify verifies a signature with the public key
	Verify(publicKey interface{}, hash []byte, signature []byte) bool
}

// AddressGenerator defines the interface for address generation
type AddressGenerator interface {
	// GenerateAddress generates an address from a public key
	GenerateAddress(publicKey interface{}) (string, error)

	// ValidateAddress validates if an address is valid
	ValidateAddress(address string) bool
}

// ECDSAAlgorithm implements the Algorithm interface for ECDSA
type ECDSAAlgorithm struct{}

// Name returns "ecdsa"
func (a *ECDSAAlgorithm) Name() string {
	return "ecdsa"
}

// GenerateKeyPair generates a new ECDSA key pair
func (a *ECDSAAlgorithm) GenerateKeyPair() (interface{}, interface{}, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// PrivateKeyToBytes converts an ECDSA private key to bytes
func (a *ECDSAAlgorithm) PrivateKeyToBytes(privateKey interface{}) ([]byte, error) {
	privKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid ECDSA private key")
	}
	return crypto.FromECDSA(privKey), nil
}

// PublicKeyToBytes converts an ECDSA public key to bytes
func (a *ECDSAAlgorithm) PublicKeyToBytes(publicKey interface{}) ([]byte, error) {
	pubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid ECDSA public key")
	}
	return crypto.FromECDSAPub(pubKey), nil
}

// BytesToPrivateKey converts bytes to an ECDSA private key
func (a *ECDSAAlgorithm) BytesToPrivateKey(data []byte) (interface{}, error) {
	return crypto.ToECDSA(data)
}

// BytesToPublicKey converts bytes to an ECDSA public key
func (a *ECDSAAlgorithm) BytesToPublicKey(data []byte) (interface{}, error) {
	pubKey, err := crypto.UnmarshalPubkey(data)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// Sign signs a hash with the ECDSA private key
func (a *ECDSAAlgorithm) Sign(privateKey interface{}, hash []byte) ([]byte, error) {
	privKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid ECDSA private key")
	}
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return nil, err
	}

	// Combine r and s into a single signature
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure r and s are 32 bytes each
	if len(rBytes) < 32 {
		rBytes = append(make([]byte, 32-len(rBytes)), rBytes...)
	}
	if len(sBytes) < 32 {
		sBytes = append(make([]byte, 32-len(sBytes)), sBytes...)
	}

	return append(rBytes, sBytes...), nil
}

// Verify verifies a signature with the ECDSA public key
func (a *ECDSAAlgorithm) Verify(publicKey interface{}, hash []byte, signature []byte) bool {
	pubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(pubKey, hash, r, s)
}

// ETHAddressGenerator implements the AddressGenerator interface for Ethereum
type ETHAddressGenerator struct{}

// GenerateAddress generates an Ethereum address from a public key
func (g *ETHAddressGenerator) GenerateAddress(publicKey interface{}) (string, error) {
	pubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("invalid ECDSA public key")
	}
	return crypto.PubkeyToAddress(*pubKey).Hex(), nil
}

// ValidateAddress validates if an address is a valid Ethereum address
func (g *ETHAddressGenerator) ValidateAddress(address string) bool {
	if len(address) != 40 && len(address) != 42 {
		return false
	}

	if len(address) == 42 {
		if address[0] != '0' || address[1] != 'x' {
			return false
		}
		address = address[2:]
	}

	_, err := hex.DecodeString(address)
	return err == nil
}

// DefaultAlgorithm returns the default ECDSA algorithm
func DefaultAlgorithm() Algorithm {
	return &ECDSAAlgorithm{}
}

// DefaultAddressGenerator returns the default Ethereum address generator
func DefaultAddressGenerator() AddressGenerator {
	return &ETHAddressGenerator{}
}

// Key 表示加密密钥，支持多种区块链平台
type Key struct {
	// Address is the blockchain address
	Address string `json:"address"`

	// PrivateKey is the private key (type depends on algorithm)
	PrivateKey interface{} `json:"-"`

	// PublicKey is the public key (type depends on algorithm)
	PublicKey interface{} `json:"-"`

	// Algorithm is the name of the cryptographic algorithm
	Algorithm string `json:"algorithm"`

	// CreatedAt is the timestamp when the key was created
	CreatedAt int64 `json:"created_at"`
}

// KeyStoreFile 表示存储在文件系统中的密钥文件格式
type KeyStoreFile struct {
	Version   int                    `json:"version"`
	ID        string                 `json:"id"`
	Address   string                 `json:"address"`
	Algorithm string                 `json:"algorithm"`
	Crypto    map[string]interface{} `json:"crypto"`
}

// KeyStoreOptions 表示密钥存储选项
type KeyStoreOptions struct {
	// Scrypt参数 - 用于密钥派生函数
	ScryptN int `json:"scryptN"`
	ScryptR int `json:"scryptR"`
	ScryptP int `json:"scryptP"`

	// 密码策略配置
	MinPasswordLen     int  `json:"minPasswordLen"`
	MaxPasswordLen     int  `json:"maxPasswordLen"`
	PasswordComplexity bool `json:"passwordComplexity"`

	// Algorithm configuration
	Algorithm        string `json:"algorithm"`
	AddressGenerator string `json:"address_generator"`
}

// DefaultKeyStoreOptions 返回默认的密钥存储选项
func DefaultKeyStoreOptions() *KeyStoreOptions {
	return &KeyStoreOptions{
		// Scrypt参数 - 与Geth标准兼容
		ScryptN: 1 << 18, // 262,144
		ScryptR: 8,
		ScryptP: 1,

		// 密码策略 - 合理的默认值
		MinPasswordLen:     8,
		MaxPasswordLen:     512,
		PasswordComplexity: true,

		// 默认算法和地址生成器
		Algorithm:        "ecdsa",
		AddressGenerator: "eth",
	}
}

// KeyStoreConfig 表示完整的密钥存储配置
type KeyStoreConfig struct {
	Path             string
	Options          *KeyStoreOptions
	Algorithm        Algorithm
	AddressGenerator AddressGenerator
}

// DefaultKeyStoreConfig 返回默认的密钥存储配置
func DefaultKeyStoreConfig(path string) *KeyStoreConfig {
	options := DefaultKeyStoreOptions()
	return &KeyStoreConfig{
		Path:             path,
		Options:          options,
		Algorithm:        DefaultAlgorithm(),
		AddressGenerator: DefaultAddressGenerator(),
	}
}

// GetAlgorithm returns the algorithm instance based on name
func GetAlgorithm(name string) (Algorithm, error) {
	switch name {
	case "ecdsa":
		return &ECDSAAlgorithm{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", name)
	}
}

// GetAddressGenerator returns the address generator instance based on name
func GetAddressGenerator(name string) (AddressGenerator, error) {
	switch name {
	case "eth":
		return &ETHAddressGenerator{}, nil
	default:
		return nil, fmt.Errorf("unsupported address generator: %s", name)
	}
}

// GenerateKeyPair 生成新的密钥对
func GenerateKeyPair(algorithm Algorithm) (interface{}, interface{}, error) {
	return algorithm.GenerateKeyPair()
}
