// Package keystore provides secure key management functionality compatible with Geth
package keystore

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// 导出go-ethereum的错误常量，保持API兼容性
var (
	ErrInvalidPassword    = keystore.ErrDecrypt
	ErrInvalidKeyFile     = errors.New("invalid key file")
	ErrUnsupportedCipher  = errors.New("unsupported cipher")
	ErrUnsupportedKDF     = errors.New("unsupported key derivation function")
	ErrInvalidMAC         = keystore.ErrDecrypt
	ErrPasswordTooShort   = errors.New("password too short")
	ErrPasswordTooLong    = errors.New("password too long")
	ErrPasswordNotComplex = errors.New("password not complex enough")
	// 改为使用函数创建包含具体文件路径的错误
	ErrKeyAlreadyExists = errors.New("key with this address already exists")
	ErrInvalidUUID      = errors.New("invalid UUID format")
)

// FileNotFoundError 返回包含具体文件路径的错误
func FileNotFoundError(filePath string) error {
	return fmt.Errorf("key file not found: %s", filePath)
}

// NewKeyFromECDSA creates a Key structure from an ECDSA private key
// 使用go-ethereum的crypto包从私钥创建Key结构
func NewKeyFromECDSA(privateKey *ecdsa.PrivateKey) (*Key, error) {
	// 计算地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// 创建通用Key结构
	return &Key{
		Address:    address.Hex(),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "ecdsa",
		CreatedAt:  time.Now().Unix(),
	}, nil
}

// EncryptKey 加密密钥，支持多种加密方案
// 将密钥使用密码加密并返回加密后的JSON数据
func EncryptKey(key *Key, password string, options *KeyStoreOptions) ([]byte, error) {
	// 验证密码
	if err := validatePassword(password, options); err != nil {
		return nil, err
	}

	// 对于ECDSA密钥，使用go-ethereum的加密功能
	if ecdsaKey, ok := key.PrivateKey.(*ecdsa.PrivateKey); ok {
		// 创建临时的go-ethereum Key结构用于加密
		ethKey := &keystore.Key{
			Address:    common.HexToAddress(key.Address),
			PrivateKey: ecdsaKey,
		}

		// 使用go-ethereum的加密功能
		encryptedData, err := keystore.EncryptKey(ethKey, password, options.ScryptN, options.ScryptP)
		if err != nil {
			return nil, err
		}

		// 修改加密数据，添加算法信息
		var keyStoreFile KeyStoreFile
		if err := json.Unmarshal(encryptedData, &keyStoreFile); err != nil {
			return nil, err
		}
		keyStoreFile.Algorithm = key.Algorithm

		return json.Marshal(keyStoreFile)
	}

	return nil, fmt.Errorf("unsupported private key type: %T", key.PrivateKey)
}

// DecryptKey 解密密钥，支持多种加密方案
// 从加密的JSON数据中解密出密钥
func DecryptKey(keyJSON []byte, password string) (*Key, error) {
	// 解析密钥文件，获取算法信息
	var keyStoreFile KeyStoreFile
	if err := json.Unmarshal(keyJSON, &keyStoreFile); err != nil {
		return nil, err
	}

	// 对于ECDSA密钥，使用go-ethereum的解密功能
	if keyStoreFile.Algorithm == "ecdsa" || keyStoreFile.Algorithm == "" {
		// 使用go-ethereum的解密功能
		ethKey, err := keystore.DecryptKey(keyJSON, password)
		if err != nil {
			return nil, err
		}

		// 转换为通用Key结构
		return &Key{
			Address:    ethKey.Address.Hex(),
			PrivateKey: ethKey.PrivateKey,
			PublicKey:  &ethKey.PrivateKey.PublicKey,
			Algorithm:  "ecdsa",
			CreatedAt:  time.Now().Unix(),
		}, nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %s", keyStoreFile.Algorithm)
}

// validatePassword validates a password against the provided options
// 验证密码是否符合安全要求
func validatePassword(password string, options *KeyStoreOptions) error {
	if len(password) < options.MinPasswordLen {
		return ErrPasswordTooShort
	}

	if len(password) > options.MaxPasswordLen {
		return ErrPasswordTooLong
	}

	if options.PasswordComplexity {
		// 检查密码复杂度（至少包含一个数字和一个字母）
		hasLetter := false
		hasDigit := false

		for _, char := range password {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
				hasLetter = true
			} else if char >= '0' && char <= '9' {
				hasDigit = true
			}
		}

		if !hasLetter || !hasDigit {
			return ErrPasswordNotComplex
		}
	}

	return nil
}

// SaveKeyStoreFile 保存密钥文件，支持多种区块链平台
// 将加密后的密钥保存到磁盘
func SaveKeyStoreFile(keyJSON []byte, dir string) (string, error) {
	// 确保目录存在
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// 解析密钥文件以获取地址和算法
	var keyStoreFile KeyStoreFile
	if err := json.Unmarshal(keyJSON, &keyStoreFile); err != nil {
		return "", fmt.Errorf("failed to unmarshal key file: %w", err)
	}

	// 构建文件名：UTC--<yyyy-mm-dd>--<algorithm>--<address>
	timestamp := time.Now().Format("2006-01-02")
	filename := fmt.Sprintf("UTC--%s--%s--%s", timestamp, keyStoreFile.Algorithm, keyStoreFile.Address)
	filePath := filepath.Join(dir, filename)

	// 写入文件，设置权限为仅所有者可读写
	if err := os.WriteFile(filePath, keyJSON, 0600); err != nil {
		return "", fmt.Errorf("failed to write key file: %w", err)
	}

	return filePath, nil
}

// LoadKeyStoreFile 从磁盘加载密钥文件
func LoadKeyStoreFile(filePath string) ([]byte, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, FileNotFoundError(filePath)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return data, nil
}

// CreateKeystoreManager 创建一个go-ethereum兼容的keystore管理器
func CreateKeystoreManager(keydir string, options *KeyStoreOptions) *keystore.KeyStore {
	if options == nil {
		options = DefaultKeyStoreOptions()
	}

	// 使用go-ethereum的keystore.New函数创建管理器
	ks := keystore.NewKeyStore(keydir, options.ScryptN, options.ScryptP)
	return ks
}

// ImportECDSA 使用go-ethereum的keystore导入ECDSA私钥
func ImportECDSA(ks *keystore.KeyStore, privateKey *ecdsa.PrivateKey, password string) (accounts.Account, error) {
	return ks.ImportECDSA(privateKey, password)
}

// ImportKey 使用go-ethereum的keystore导入密钥文件
func ImportKey(ks *keystore.KeyStore, keyJSON []byte, oldPassword, newPassword string) (accounts.Account, error) {
	return ks.Import(keyJSON, oldPassword, newPassword)
}

// ExportKey 使用go-ethereum的keystore导出密钥
func ExportKey(ks *keystore.KeyStore, account accounts.Account, password string) ([]byte, error) {
	return ks.Export(account, password, password)
}

// FindKeyFileByAddress 通过地址查找密钥文件
func FindKeyFileByAddress(keydir, address string) (string, error) {
	// 标准化地址格式
	if !strings.HasPrefix(address, "0x") {
		address = "0x" + address
	}
	address = strings.ToLower(address)

	// 扫描keydir目录
	files, err := os.ReadDir(keydir)
	if err != nil {
		return "", err
	}

	// 查找匹配的文件
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(file.Name()), address[2:]) {
			return filepath.Join(keydir, file.Name()), nil
		}
	}

	return "", fmt.Errorf("key file for address %s not found in directory %s", address, keydir)
}

// ParseKeyStoreFile 解析密钥文件
func ParseKeyStoreFile(keyJSON []byte) error {
	// 简单验证JSON格式是否正确
	var keyStoreFile struct {
		Version int                    `json:"version"`
		Address string                 `json:"address"`
		Crypto  map[string]interface{} `json:"crypto"`
	}
	if err := json.Unmarshal(keyJSON, &keyStoreFile); err != nil {
		return fmt.Errorf("failed to parse keystore file: %w", err)
	}
	return nil
}
