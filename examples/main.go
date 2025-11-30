package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/palagend/ponk/pkg/keystore"
)

func main() {
	// 创建一个临时目录用于存储keystore文件
	tempDir, err := os.MkdirTemp("", "keystore-example")
	defer os.RemoveAll(tempDir) // 注释掉清理临时目录，以便查看文件内容
	if err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}

	fmt.Println("=== keystore库使用示例 ===")
	fmt.Printf("使用临时目录: %s\n\n", tempDir)

	// 1. 初始化KeyStore
	ks := keystore.NewKeyStore(tempDir, &keystore.KeyStoreOptions{
		ScryptN:            16384,
		ScryptR:            8,
		ScryptP:            1,
		MinPasswordLen:     6,
		MaxPasswordLen:     128,
		PasswordComplexity: true,
	})

	// 2. 创建新账户（生成密钥对并加密存储）
	fmt.Println("[1] 创建新账户")
	password := "SecurePass123"
	address, err := ks.CreateNewAccount(password)
	if err != nil {
		log.Fatalf("创建账户失败: %v", err)
	}
	fmt.Printf("\033[32m[OK]\033[0m 账户创建成功!\n")
	fmt.Printf("   地址: %s\n", address)
	fmt.Printf("   密码: %s\n\n", password)

	// 3. 检查账户是否存在
	fmt.Println("[2] 检查账户是否存在")
	exists := ks.HasAddress(address)
	fmt.Printf("\033[32m[OK]\033[0m 账户存在: %v\n\n", exists)

	// 4. 列出所有账户
	fmt.Println("[3] 列出所有账户")
	addresses, err := ks.List()
	if err != nil {
		log.Fatalf("列出账户失败: %v", err)
	}
	fmt.Printf("\033[32m[OK]\033[0m 找到 %d 个账户:\n", len(addresses))
	for _, addr := range addresses {
		fmt.Printf("   - %s\n", addr)
	}
	fmt.Println()

	// 5. 获取密钥（解密）
	fmt.Println("[4] 使用正确密码获取密钥")
	key, err := ks.GetKey(address, password)
	if err != nil {
		log.Fatalf("获取密钥失败: %v", err)
	}
	fmt.Printf("\033[32m[OK]\033[0m 密钥获取成功!\n")
	fmt.Printf("   ID: %s\n", key.Id.String())
	fmt.Printf("   地址: %s\n", key.Address.Hex())
	fmt.Printf("   公钥: X=%x, Y=%x\n\n", key.PrivateKey.PublicKey.X.Bytes(), key.PrivateKey.PublicKey.Y.Bytes())

	// 6. 错误密码测试
	fmt.Println("[5] 使用错误密码尝试获取密钥")
	wrongPassword := "WrongPassword456"
	_, err = ks.GetKey(address, wrongPassword)
	if err != nil {
		fmt.Printf("\033[32m[OK]\033[0m 正确拒绝了错误密码: %v\n\n", err)
	} else {
		log.Fatalf("\033[31m[ERR]\033[0m 错误: 错误密码被接受")
	}

	// 7. 导出密钥文件
	fmt.Println("[6] 导出密钥文件内容")
	keyJSON, err := ks.ExportKey(address, password)
	if err != nil {
		log.Fatalf("导出密钥文件失败: %v", err)
	}
	fmt.Printf("\033[32m[OK]\033[0m 密钥文件导出成功!\n")
	fmt.Printf("   密钥文件大小: %d 字节\n", len(keyJSON))
	fmt.Printf("   文件内容预览: %s...\n\n", string(keyJSON)[:100])

	// 8. 显示生成的文件
	fmt.Println("[7] 显示生成的keystore文件")
	files, err := filepath.Glob(filepath.Join(tempDir, "UTC--*"))
	if err != nil {
		log.Fatalf("查找keystore文件失败: %v", err)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			log.Printf("获取文件信息失败: %v", err)
			continue
		}
		fmt.Printf("\033[32m[OK]\033[0m 找到文件: %s\n", filepath.Base(file))
		fmt.Printf("   大小: %d 字节\n", info.Size())
		// 读取并显示完整的keystore文件内容
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("读取文件内容失败: %v", err)
		} else {
			fmt.Printf("   文件完整内容:\n")
			fmt.Println(string(content))
		}
	}
	fmt.Println()

	// 9. 删除账户
	fmt.Println("[8] 删除账户")
	err = ks.Delete(address, password)
	if err != nil {
		log.Fatalf("删除账户失败: %v", err)
	}
	fmt.Printf("\033[32m[OK]\033[0m 账户删除成功!\n")

	// 10. 验证删除结果
	exists = ks.HasAddress(address)
	fmt.Printf("\033[32m[OK]\033[0m 账户是否仍然存在: %v\n\n", exists)

	fmt.Println("=== 示例演示完成 ===")
	fmt.Println("所有keystore功能均正常工作!")
}
