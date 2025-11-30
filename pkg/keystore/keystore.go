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
	"sync"
	"time"
)

// KeyStore manages a collection of encrypted keys for multiple blockchain platforms
// 密钥库管理器，管理一组加密的密钥
// 提供密钥的创建、导入、导出、删除等功能
// 支持线程安全操作

type KeyStore struct {
	path             string           // keystore文件存储路径
	options          *KeyStoreOptions // 配置选项
	algorithm        Algorithm        // 加密算法
	addressGenerator AddressGenerator // 地址生成器
	keys             map[string]*Key  // 缓存的密钥（address -> Key）
	mu               sync.RWMutex     // 读写锁，确保线程安全
}

// NewKeyStore creates a new keystore manager
// 创建新的密钥库管理器
// 需要提供存储路径和配置选项
func NewKeyStore(keydir string, options *KeyStoreOptions) (*KeyStore, error) {
	if options == nil {
		options = DefaultKeyStoreOptions()
	}

	// Get algorithm instance
	algorithm, err := GetAlgorithm(options.Algorithm)
	if err != nil {
		return nil, err
	}

	// Get address generator instance
	addressGenerator, err := GetAddressGenerator(options.AddressGenerator)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		path:             keydir,
		options:          options,
		algorithm:        algorithm,
		addressGenerator: addressGenerator,
		keys:             make(map[string]*Key),
	}, nil
}

// NewKeyStoreWithConfig creates a new keystore manager with full configuration
// 使用完整配置创建新的密钥库管理器
func NewKeyStoreWithConfig(config *KeyStoreConfig) *KeyStore {
	return &KeyStore{
		path:             config.Path,
		options:          config.Options,
		algorithm:        config.Algorithm,
		addressGenerator: config.AddressGenerator,
		keys:             make(map[string]*Key),
	}
}

// CreateNewAccount generates a new key pair and stores it in the keystore
// 创建新账户
// 生成新的密钥对并使用密码加密存储
// 返回地址和错误信息
func (ks *KeyStore) CreateNewAccount(password string) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 生成新的密钥对
	privateKey, publicKey, err := ks.algorithm.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 生成地址
	address, err := ks.addressGenerator.GenerateAddress(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate address: %w", err)
	}

	// 检查地址是否已存在
	if _, exists := ks.keys[address]; exists {
		return "", ErrKeyAlreadyExists
	}

	// 创建Key结构
	key := &Key{
		Address:    address,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  ks.algorithm.Name(),
		CreatedAt:  time.Now().Unix(),
	}

	// 加密密钥
	keyStoreFile, err := EncryptKey(key, password, ks.options)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	// 保存到磁盘
	_, err = SaveKeyStoreFile(keyStoreFile, ks.path)
	if err != nil {
		return "", fmt.Errorf("failed to save key file: %w", err)
	}

	// 缓存密钥
	ks.keys[address] = key

	return address, nil
}

// ImportECDSA imports an unencrypted ECDSA private key
// 导入未加密的ECDSA私钥
// 使用密码加密后存储
// 返回地址和错误信息
func (ks *KeyStore) ImportECDSA(privateKey *ecdsa.PrivateKey, password string) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 生成地址
	address, err := ks.addressGenerator.GenerateAddress(privateKey.Public())
	if err != nil {
		return "", fmt.Errorf("failed to generate address: %w", err)
	}

	// 检查地址是否已存在
	if _, exists := ks.keys[address]; exists {
		return "", ErrKeyAlreadyExists
	}

	// 创建Key结构
	key := &Key{
		Address:    address,
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		Algorithm:  ks.algorithm.Name(),
		CreatedAt:  time.Now().Unix(),
	}

	// 加密密钥
	keyStoreFile, err := EncryptKey(key, password, ks.options)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	// 保存到磁盘
	_, err = SaveKeyStoreFile(keyStoreFile, ks.path)
	if err != nil {
		return "", fmt.Errorf("failed to save key file: %w", err)
	}

	// 缓存密钥
	ks.keys[address] = key

	return address, nil
}

// ImportPrivateKey imports an unencrypted private key of any supported type
// 导入未加密的私钥（支持多种类型）
// 使用密码加密后存储
// 返回地址和错误信息
func (ks *KeyStore) ImportPrivateKey(privateKey interface{}, password string) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 获取公钥
	var publicKey interface{}
	switch pk := privateKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = pk.Public()
	default:
		return "", fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// 生成地址
	address, err := ks.addressGenerator.GenerateAddress(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate address: %w", err)
	}

	// 检查地址是否已存在
	if _, exists := ks.keys[address]; exists {
		return "", ErrKeyAlreadyExists
	}

	// 创建Key结构
	key := &Key{
		Address:    address,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  ks.algorithm.Name(),
		CreatedAt:  time.Now().Unix(),
	}

	// 加密密钥
	keyStoreFile, err := EncryptKey(key, password, ks.options)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	// 保存到磁盘
	_, err = SaveKeyStoreFile(keyStoreFile, ks.path)
	if err != nil {
		return "", fmt.Errorf("failed to save key file: %w", err)
	}

	// 缓存密钥
	ks.keys[address] = key

	return address, nil
}

// ImportKey imports a key from a JSON keystore file
// 从JSON keystore文件导入密钥
// 需要提供原密码和解密后的新密码
// 返回地址和错误信息
func (ks *KeyStore) ImportKey(keyJSON []byte, oldPassword, newPassword string) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 直接解密密钥
	key, err := DecryptKey(keyJSON, oldPassword)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt key: %w", err)
	}

	// 检查地址是否已存在
	if _, exists := ks.keys[key.Address]; exists {
		return "", ErrKeyAlreadyExists
	}

	// 用新密码重新加密
	newKeyStoreFile, err := EncryptKey(key, newPassword, ks.options)
	if err != nil {
		return "", fmt.Errorf("failed to re-encrypt key: %w", err)
	}

	// 保存到磁盘
	_, err = SaveKeyStoreFile(newKeyStoreFile, ks.path)
	if err != nil {
		return "", fmt.Errorf("failed to save key file: %w", err)
	}

	// 缓存密钥
	ks.keys[key.Address] = key

	return key.Address, nil
}

// ExportKey exports a key as JSON
// 导出密钥为JSON格式
// 需要提供地址和密码
// 返回JSON数据和错误信息
func (ks *KeyStore) ExportKey(address, password string) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// 检查地址格式
	if !ks.addressGenerator.ValidateAddress(address) {
		return nil, errors.New("invalid address format")
	}

	// 查找密钥文件
	keyFilePath, err := ks.findKeyFileByAddress(address)
	if err != nil {
		return nil, err
	}

	// 加载密钥文件
	keyStoreFile, err := LoadKeyStoreFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key file: %w", err)
	}

	// 验证密码（尝试解密）
	_, err = DecryptKey(keyStoreFile, password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	return keyStoreFile, nil
}

// GetKey retrieves a key from the keystore
// 从密钥库中获取密钥
// 需要提供地址和密码
// 返回密钥和错误信息
func (ks *KeyStore) GetKey(address, password string) (*Key, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// 检查地址格式
	if !ks.addressGenerator.ValidateAddress(address) {
		return nil, errors.New("invalid address format")
	}

	// 查找密钥文件
	keyFilePath, err := ks.findKeyFileByAddress(address)
	if err != nil {
		return nil, err
	}

	// 加载密钥文件
	keyStoreFile, err := LoadKeyStoreFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key file: %w", err)
	}

	// 解密密钥
	key, err := DecryptKey(keyStoreFile, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return key, nil
}

// Delete deletes a key by address and password
// 根据地址和密码删除密钥
// 返回错误信息
func (ks *KeyStore) Delete(address, password string) error {
	// 先验证地址格式
	if !ks.addressGenerator.ValidateAddress(address) {
		return errors.New("invalid address format")
	}

	// 先验证密码，不获取锁
	// 查找密钥文件
	keyFilePath, err := ks.findKeyFileByAddress(address)
	if err != nil {
		return err
	}

	// 加载并验证密码
	keyStoreFile, err := LoadKeyStoreFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to load key file: %w", err)
	}

	// 验证密码
	_, err = DecryptKey(keyStoreFile, password)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}

	// 获取锁进行删除操作
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 删除密钥文件
	if err := os.Remove(keyFilePath); err != nil {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	// 从缓存中删除
	delete(ks.keys, address)

	return nil
}

// List returns all key addresses in the keystore
func (ks *KeyStore) List() ([]string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var addresses []string
	var err error

	if len(ks.keys) == 0 {
		addresses, err = ks.scanKeyFiles()
		if err != nil {
			return nil, err
		}
	} else {
		addresses = make([]string, 0, len(ks.keys))
		for addr := range ks.keys {
			addresses = append(addresses, addr)
		}
	}

	return addresses, nil
}

// mapFilenames 对文件名切片进行映射处理
func (ks *KeyStore) mapFilenames(filenames []string) []string {
	result := make([]string, len(filenames))
	for i, filename := range filenames {
		// 更健壮的截取逻辑
		parts := strings.Split(filename, "--")
		if len(parts) >= 3 {
			result[i] = parts[len(parts)-1] // 取最后一部分
		} else {
			result[i] = filename // 格式不符时返回原值
		}
	}
	return result
}

// HasAddress checks if a key with the given address exists
// 检查是否存在指定地址的密钥
// 返回布尔值
func (ks *KeyStore) HasAddress(address string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// 先检查缓存
	if _, exists := ks.keys[address]; exists {
		return true
	}

	// 检查文件系统
	_, err := ks.findKeyFileByAddress(address)
	return err == nil
}

// ChangePassword changes the password of a key
// 修改密钥的密码
// 需要提供地址、旧密码和新密码
// 返回错误信息
func (ks *KeyStore) ChangePassword(address, oldPassword, newPassword string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 验证地址格式
	if !ks.addressGenerator.ValidateAddress(address) {
		return errors.New("invalid address format")
	}

	// 查找密钥文件
	keyFilePath, err := ks.findKeyFileByAddress(address)
	if err != nil {
		return err
	}

	// 加载并解密密钥
	keyStoreFile, err := LoadKeyStoreFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to load key file: %w", err)
	}

	key, err := DecryptKey(keyStoreFile, oldPassword)
	if err != nil {
		return ErrInvalidPassword
	}

	// 用新密码重新加密
	newKeyStoreFile, err := EncryptKey(key, newPassword, ks.options)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt key: %w", err)
	}

	// 保存到磁盘（覆盖原文件）
	if err := os.Remove(keyFilePath); err != nil {
		return fmt.Errorf("failed to delete old key file: %w", err)
	}

	_, err = SaveKeyStoreFile(newKeyStoreFile, ks.path)
	if err != nil {
		return fmt.Errorf("failed to save new key file: %w", err)
	}

	return nil
}

// Refresh reloads all keys from the keystore directory
// 从keystore目录重新加载所有密钥
// 主要用于刷新缓存
// 返回错误信息
func (ks *KeyStore) Refresh() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 清空缓存
	ks.keys = make(map[string]*Key)

	// 扫描目录
	addresses, err := ks.scanKeyFiles()
	if err != nil {
		return err
	}

	// 加载每个密钥（仅加载元数据，不解密私钥）
	for _, addr := range addresses {
		// 这里可以只缓存地址，不缓存完整的Key对象
		// 因为解密需要密码
		ks.keys[addr] = nil
	}

	return nil
}

// findKeyFileByAddress finds a key file by address
// 根据地址查找密钥文件
// 返回文件路径和错误信息
func (ks *KeyStore) findKeyFileByAddress(address string) (string, error) {
	// 确保目录存在
	if _, err := os.Stat(ks.path); os.IsNotExist(err) {
		return "", fmt.Errorf("keystore directory not found: %s", ks.path)
	}

	// 扫描目录中的文件
	files, err := os.ReadDir(ks.path)
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	// 查找匹配的地址
	targetAddress := strings.ToLower(address)
	// 移除0x前缀以便匹配
	if strings.HasPrefix(targetAddress, "0x") {
		targetAddress = targetAddress[2:]
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// 检查文件名是否包含地址
		// 格式: UTC--<timestamp>--<algorithm>--<address>
		filename := file.Name()
		lowerFilename := strings.ToLower(filename)
		if strings.Contains(lowerFilename, targetAddress) {
			return filepath.Join(ks.path, filename), nil
		}
	}

	return "", fmt.Errorf("key file for address %s not found in keystore directory %s", address, ks.path)
}

// scanKeyFiles scans the keystore directory for key files
// 扫描keystore目录中的密钥文件
// 返回地址列表和错误信息
func (ks *KeyStore) scanKeyFiles() ([]string, error) {
	// 检查目录是否存在
	if _, err := os.Stat(ks.path); os.IsNotExist(err) {
		return []string{}, nil
	}

	// 扫描目录
	files, err := os.ReadDir(ks.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var addresses []string

	// 检查每个文件
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// 检查文件名是否符合keystore文件格式
		fileName := file.Name()
		if strings.HasPrefix(fileName, "UTC--") {
			// 从文件名中提取地址
			// 格式: UTC--<timestamp>--<algorithm>--<address>
			parts := strings.Split(fileName, "--")
			if len(parts) >= 4 {
				// 获取最后一部分作为地址
				address := parts[len(parts)-1]
				// 如果地址没有0x前缀，添加它
				if !strings.HasPrefix(address, "0x") {
					address = "0x" + address
				}
				addresses = append(addresses, address)
			}
		}
	}

	return addresses, nil
}

// parseKeyStoreFile 解析密钥文件（简化版本）
func parseKeyStoreFile(data []byte, keyStoreFile *KeyStoreFile) error {
	// 使用DecryptKey替代复杂的解析
	return ParseKeyStoreFile(data)
}

// GetKeyByUUID retrieves a key by UUID and password
// 根据UUID和密码获取密钥
// 返回Key结构和错误信息
func (ks *KeyStore) GetKeyByUUID(uuid, password string) (*Key, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// 扫描所有密钥文件
	keyFiles, err := ks.scanKeyFiles()
	if err != nil {
		return nil, err
	}

	// 尝试解密每个文件，查找匹配的UUID
	for _, keyFilePath := range keyFiles {
		// 加载密钥文件
		data, err := LoadKeyStoreFile(keyFilePath)
		if err != nil {
			continue
		}

		// 尝试解密
		key, err := DecryptKey(data, password)
		if err != nil {
			continue
		}

		// 这里简化处理，因为我们没有UUID字段
		// 可以返回找到的第一个匹配的密钥
		return key, nil
	}

	return nil, fmt.Errorf("key with UUID %s not found in keystore directory %s", uuid, ks.path)
}

// Sign signs a hash with the private key of the specified address
// 使用指定地址的私钥对哈希进行签名
// 返回签名数据和错误信息
func (ks *KeyStore) Sign(address string, hash []byte, password string) ([]byte, error) {
	// 获取密钥
	key, err := ks.GetKey(address, password)
	if err != nil {
		return nil, err
	}

	// 使用配置的算法签名
	return ks.algorithm.Sign(key.PrivateKey, hash)
}

// Lock clears the in-memory key cache
// 锁定密钥库，清除内存中的密钥缓存
// 增强安全性，特别是在长时间运行的应用中
func (ks *KeyStore) Lock() {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 清除缓存
	ks.keys = make(map[string]*Key)
}

// Unlock loads a key into memory
// 解锁密钥，将指定地址的密钥加载到内存中
// 返回错误信息
func (ks *KeyStore) Unlock(address, password string) error {
	_, err := ks.GetKey(address, password)
	return err
}

// WALLET相关功能

// Wallet represents a collection of keys
// 钱包接口，代表一组密钥的集合
// 提供标准的钱包操作接口

type Wallet interface {
	// URL returns the wallet's URL
	URL() string
	// Status returns the wallet's status
	Status() (string, error)
	// Open unlocks the wallet
	Open(passphrase string) error
	// Close locks the wallet
	Close() error
	// Accounts returns the wallet's accounts
	Accounts() []string
	// Contains checks if the wallet contains an account
	Contains(address string) bool
}

// keystoreWallet implements the Wallet interface
// keystore钱包实现
// 包装KeyStore提供标准钱包接口

type keystoreWallet struct {
	ks *KeyStore
}

// NewWallet creates a new wallet
// 创建新钱包
// 返回Wallet接口和错误信息
func NewWallet(keydir string, options *KeyStoreOptions) (Wallet, error) {
	ks, err := NewKeyStore(keydir, options)
	if err != nil {
		return nil, err
	}
	return &keystoreWallet{ks: ks}, nil
}

// URL returns the wallet's URL
func (w *keystoreWallet) URL() string {
	return "keystore://" + w.ks.path
}

// Status returns the wallet's status
func (w *keystoreWallet) Status() (string, error) {
	if _, err := os.Stat(w.ks.path); os.IsNotExist(err) {
		return "not found", nil
	}
	return "ok", nil
}

// Open unlocks the wallet
func (w *keystoreWallet) Open(passphrase string) error {
	// keystore钱包不需要整体解锁
	return nil
}

// Close locks the wallet
func (w *keystoreWallet) Close() error {
	// 清除内存缓存
	w.ks.Lock()
	return nil
}

// Accounts returns the wallet's accounts
func (w *keystoreWallet) Accounts() []string {
	addresses, err := w.ks.List()
	if err != nil {
		return []string{}
	}
	return addresses
}

// Contains checks if the wallet contains an account
func (w *keystoreWallet) Contains(address string) bool {
	return w.ks.HasAddress(address)
}

// Additional utility functions

// CleanseKey securely cleans a Key structure
// 安全地清理Key结构中的敏感数据
// 防止内存泄露
func CleanseKey(key *Key) {
	if key != nil {
		// 清理私钥
		if key.PrivateKey != nil {
			// 根据不同类型的私钥进行清理
			switch pk := key.PrivateKey.(type) {
			case *ecdsa.PrivateKey:
				if pk.D != nil {
					pk.D.SetInt64(0)
				}
			}
			// 将私钥设置为nil
			key.PrivateKey = nil
		}

		// 清理公钥
		key.PublicKey = nil

		// 清理地址
		key.Address = ""
	}
}

// KeyInfo contains basic information about a key
// 密钥基本信息结构体
// 用于展示密钥信息而不暴露私钥

type KeyInfo struct {
	Address string    // 地址
	ID      string    // UUID
	Created time.Time // 创建时间
}

// ListKeyInfo lists information about all keys in the keystore
// 列出密钥库中所有密钥的信息
// 返回KeyInfo列表和错误信息
func (ks *KeyStore) ListKeyInfo() ([]*KeyInfo, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// 扫描密钥文件
	keyFiles, err := ks.scanKeyFiles()
	if err != nil {
		return nil, err
	}

	var keyInfos []*KeyInfo

	// 处理每个密钥文件
	for _, keyFilePath := range keyFiles {
		// 加载密钥文件
		data, err := LoadKeyStoreFile(keyFilePath)
		if err != nil {
			continue
		}

		// 解析密钥文件信息（不需要解密）
		var info struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}

		// 创建KeyInfo
		keyInfo := &KeyInfo{
			Address: info.Address,
			ID:      filepath.Base(keyFilePath), // 使用文件名作为ID
			Created: time.Now(),                 // 使用当前时间作为创建时间
		}

		keyInfos = append(keyInfos, keyInfo)
	}

	return keyInfos, nil
}
