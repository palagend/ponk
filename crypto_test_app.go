package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/palagend/ponk/pkg/keystore"
)

func main() {
	fmt.Println("测试keystore加密解密功能...")

	// 生成ECDSA私钥
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		fmt.Printf("生成私钥失败: %v\n", err)
		os.Exit(1)
	}

	// 创建Key结构
	key, err := keystore.NewKeyFromECDSA(privateKey)
	if err != nil {
		fmt.Printf("创建Key失败: %v\n", err)
		os.Exit(1)
	}

	// 创建选项，使用低强度参数进行测试
	options := keystore.DefaultKeyStoreOptions()
	// options.ScryptN = 1024
	// options.ScryptR = 8
	// options.ScryptP = 1

	// 测试加密
	password := "TestPassword123!"
	keyStoreFile, err := keystore.EncryptKey(key, password, options)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("加密成功")

	// 测试正确密码解密
	_, err = keystore.DecryptKey(keyStoreFile, password)
	if err != nil {
		fmt.Printf("使用正确密码解密失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("使用正确密码解密成功")

	// 测试错误密码解密
	wrongPassword := "WrongPassword456!"
	_, err = keystore.DecryptKey(keyStoreFile, wrongPassword)
	if err == nil {
		fmt.Println("错误：使用错误密码解密应该失败，但成功了！")
		os.Exit(1)
	}
	fmt.Println("使用错误密码解密失败,符合预期")

	fmt.Println("所有测试通过！")
}
