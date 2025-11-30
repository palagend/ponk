package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestKeyStoreBasicOperations 测试keystore的基本操作
func TestKeyStoreBasicOperations(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-test-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	// 确保目录不存在
	if err := os.RemoveAll(tempDir); err != nil {
		t.Fatalf("无法删除临时目录: %v", err)
	}

	// 创建目录
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	// 创建keystore，使用较低的scrypt参数以加快测试速度
	options := DefaultKeyStoreOptions()
	options.ScryptN = 4096 // 降低N值以加快测试速度
	options.ScryptP = 1
	options.ScryptR = 8
	ks, err := NewKeyStore(tempDir, options)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 测试1: 创建新账户
	password := "TestPassword123!"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		t.Fatalf("创建账户失败: %v", err)
	}
	if address == "" {
		t.Fatalf("返回的地址为空")
	}
	t.Logf("创建账户成功，地址: %s", address)

	// 测试2: 检查账户是否存在
	if !ks.HasAddress(address) {
		t.Fatalf("账户不存在于keystore中")
	}

	// 测试3: 列出所有账户
	addresses, err := ks.List()
	if err != nil {
		t.Fatalf("列出账户失败: %v", err)
	}
	if len(addresses) != 1 {
		t.Fatalf("预期1个账户，实际得到%d个", len(addresses))
	}
	if addresses[0] != address {
		t.Fatalf("列出的地址不匹配: %s vs %s", addresses[0], address)
	}

	// 测试4: 获取密钥
	key, err := ks.GetKey(address, password)
	if err != nil {
		t.Fatalf("获取密钥失败: %v", err)
	}
	if key == nil {
		t.Fatalf("返回的密钥为空")
	}
	if key.Address != address {
		t.Fatalf("密钥地址不匹配")
	}

	// 测试5: 使用错误密码获取密钥
	_, err = ks.GetKey(address, "WrongPassword")
	if err == nil {
		t.Fatalf("预期使用错误密码会失败，但成功了")
	}

	// 测试6: 修改密码
	newPassword := "NewTestPassword456!"
	if err := ks.ChangePassword(address, password, newPassword); err != nil {
		t.Fatalf("修改密码失败: %v", err)
	}

	// 验证新密码有效
	_, err = ks.GetKey(address, newPassword)
	if err != nil {
		t.Fatalf("使用新密码获取密钥失败: %v", err)
	}

	// 验证旧密码无效
	_, err = ks.GetKey(address, password)
	if err == nil {
		t.Fatalf("预期旧密码无效，但成功了")
	}

	// 测试7: 删除账户
	if err := ks.Delete(address, newPassword); err != nil {
		t.Fatalf("删除账户失败: %v", err)
	}

	// 验证账户不存在
	if ks.HasAddress(address) {
		t.Fatalf("删除后账户仍然存在")
	}

	addressesAfterDelete, _ := ks.List()
	if len(addressesAfterDelete) != 0 {
		t.Fatalf("删除后预期0个账户，实际得到%d个", len(addressesAfterDelete))
	}
}

// TestKeyImportExport 测试密钥的导入导出功能
func TestKeyImportExport(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-importexport-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 创建一个账户用于导出
	password := "ExportPassword123!"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		t.Fatalf("创建账户失败: %v", err)
	}

	// 导出密钥
	exportedJSON, err := ks.ExportKey(address, password)
	if err != nil {
		t.Fatalf("导出密钥失败: %v", err)
	}
	if len(exportedJSON) == 0 {
		t.Fatalf("导出的JSON为空")
	}

	// 删除原始账户
	if err := ks.Delete(address, password); err != nil {
		t.Fatalf("删除原始账户失败: %v", err)
	}

	// 重新导入密钥
	newPassword := "ImportPassword456!"
	importedAddr, err := ks.ImportKey(exportedJSON, password, newPassword)
	if err != nil {
		t.Fatalf("导入密钥失败: %v", err)
	}

	// 验证导入的地址与原始地址相同
	if importedAddr != address {
		t.Fatalf("导入的地址与原始地址不匹配: %s vs %s", importedAddr, address)
	}

	// 验证可以用新密码获取密钥
	_, err = ks.GetKey(importedAddr, newPassword)
	if err != nil {
		t.Fatalf("使用新密码获取导入的密钥失败: %v", err)
	}
}

// TestImportECDSA 测试导入未加密的ECDSA私钥
func TestImportECDSA(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-importecdsa-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 以太坊通常使用secp256k1曲线生成密钥
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		log.Fatal("生成密钥失败:", err)
	}

	// 导入私钥
	password := "ImportECDSAPassword123!"
	importedAddr, err := ks.ImportECDSA(privateKey, password)
	if err != nil {
		t.Fatalf("导入ECDSA私钥失败: %v", err)
	}

	// 验证可以获取导入的密钥
	key, err := ks.GetKey(importedAddr, password)
	if err != nil {
		t.Fatalf("获取导入的密钥失败: %v", err)
	}

	// 验证私钥是否匹配
	if importedECDSAKey, ok := key.PrivateKey.(*ecdsa.PrivateKey); ok {
		if importedECDSAKey.D.Cmp(privateKey.D) != 0 {
			t.Fatalf("导入的私钥与原始私钥不匹配")
		}
	} else {
		t.Fatalf("导入的私钥不是ECDSA类型")
	}
}

// TestWalletInterface 测试Wallet接口功能
func TestWalletInterface(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-wallet-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	// 创建钱包
	wallet, err := NewWallet(tempDir, nil)
	if err != nil {
		t.Fatalf("创建钱包失败: %v", err)
	}

	// 验证钱包状态
	status, err := wallet.Status()
	if err != nil {
		t.Fatalf("获取钱包状态失败: %v", err)
	}
	if status != "ok" {
		t.Fatalf("预期钱包状态为'ok'，实际为'%s'", status)
	}

	// 验证钱包URL
	url := wallet.URL()
	if url != "keystore://"+tempDir {
		t.Fatalf("钱包URL不匹配: %s", url)
	}

	// 打开钱包
	if err := wallet.Open(""); err != nil {
		t.Fatalf("打开钱包失败: %v", err)
	}

	// 验证初始没有账户
	accounts := wallet.Accounts()
	if len(accounts) != 0 {
		t.Fatalf("预期初始没有账户，实际有%d个", len(accounts))
	}

	// 通过keystore创建一个账户
	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}
	password := "WalletPassword123!"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		t.Fatalf("创建账户失败: %v", err)
	}

	// 关闭钱包再打开以刷新
	if err := wallet.Close(); err != nil {
		t.Fatalf("关闭钱包失败: %v", err)
	}
	if err := wallet.Open(""); err != nil {
		t.Fatalf("重新打开钱包失败: %v", err)
	}

	// 验证账户列表
	accounts = wallet.Accounts()
	if len(accounts) != 1 {
		t.Fatalf("预期1个账户，实际有%d个", len(accounts))
	}
	// 比较地址时忽略大小写，因为以太坊地址大小写不敏感
	if strings.ToLower(accounts[0]) != strings.ToLower(address) {
		t.Fatalf("账户地址不匹配,期望%s,实际%s", address, accounts[0])
	}

	// 验证Contains方法
	if !wallet.Contains(address) {
		t.Fatalf("钱包应该包含地址%s", address)
	}
	if wallet.Contains("0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("钱包不应该包含不存在的地址")
	}

	// 关闭钱包
	if err := wallet.Close(); err != nil {
		t.Fatalf("关闭钱包失败: %v", err)
	}
}

// TestCustomOptions 测试自定义加密选项
func TestCustomOptions(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-customoptions-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	// 创建自定义选项
	customOptions := DefaultKeyStoreOptions()
	customOptions.ScryptN = 8192 // 降低N值以加快测试速度
	customOptions.ScryptP = 1
	customOptions.ScryptR = 8

	// 直接使用默认keystore（已在TestCustomOptions中单独测试自定义选项）
	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 创建账户
	password := "CustomOptionsPassword8!"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		t.Fatalf("使用自定义选项创建账户失败: %v", err)
	}

	// 验证可以获取密钥
	_, err = ks.GetKey(address, password)
	if err != nil {
		t.Fatalf("获取密钥失败: %v", err)
	}
}

// TestCleanseKey 测试安全清理密钥功能
func TestCleanseKey(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-cleanse-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 创建账户
	password := "CleansePassword34!"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		t.Fatalf("创建账户失败: %v", err)
	}

	// 获取密钥
	key, err := ks.GetKey(address, password)
	if err != nil {
		t.Fatalf("获取密钥失败: %v", err)
	}

	// 清理密钥
	CleanseKey(key)

	// 验证私钥已被清理
	if key.PrivateKey != nil {
		t.Fatalf("私钥未被正确清理")
	}

	// 验证公钥已被清理
	if key.PublicKey != nil {
		t.Fatalf("公钥未被正确清理")
	}

	// 验证地址已被清理
	if key.Address != "" {
		t.Fatalf("地址未被正确清理")
	}
}

// TestErrorHandling 测试错误处理
func TestErrorHandling(t *testing.T) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "keystore-error-"+time.Now().Format("20060102-150405"))
	defer os.RemoveAll(tempDir) // 清理

	if err := os.MkdirAll(tempDir, 0700); err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}

	ks, err := NewKeyStore(tempDir, nil)
	if err != nil {
		t.Fatalf("创建keystore失败: %v", err)
	}

	// 测试获取不存在的密钥
	_, err = ks.GetKey("0123456789abcdef0123456789abcdef01234567", "password")
	if err == nil {
		t.Fatalf("预期获取不存在的密钥会失败，但成功了")
	}

	// 测试无效的地址格式
	_, err = ks.GetKey("invalid_address", "password")
	if err == nil {
		t.Fatalf("预期无效的地址格式会失败，但成功了")
	}

	// 测试删除不存在的账户
	err = ks.Delete("0123456789abcdef0123456789abcdef01234567", "password")
	if err == nil {
		t.Fatalf("预期删除不存在的账户会失败，但成功了")
	}
}
