// Package keystore provides secure key management functionality compatible with Geth
package keystore

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// 类型别名，使用go-ethereum的keystore包中的结构体
// Key 表示加密密钥
type Key = keystore.Key

// KeyStoreFile 表示存储在文件系统中的密钥文件格式
type KeyStoreFile struct {
	Version int                    `json:"version"`
	ID      string                 `json:"id"`
	Address string                 `json:"address"`
	Crypto  map[string]interface{} `json:"crypto"`
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
	}
}

// 辅助函数，用于处理地址转换

// HexToAddress 将十六进制地址字符串转换为Address类型
func HexToAddress(hexAddr string) common.Address {
	return common.HexToAddress(hexAddr)
}

// AddressToHex 将Address类型转换为十六进制字符串
func AddressToHex(addr common.Address) string {
	return addr.Hex()
}

// GenerateKeyPair 生成新的密钥对
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return key, &key.PublicKey, nil
}
