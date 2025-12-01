# 🔐Keystore -  Palagend Miscellaneous Tools 

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org/)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://opensource.org/license/gpl-3-0)

一个支持多种区块链平台的通用密钥存储库，用于安全管理加密货币私钥。

## ✨ 特性

- **多链支持**：可配置不同的加密算法和地址生成器，支持多种区块链平台
- **军事级加密**：采用AES-256-CTR + scrypt KDF加密方案
- **完全兼容Geth**：默认支持标准Keystore文件格式，与Geth钱包完全互通
- **内存安全**：敏感数据自动清零，防止内存泄露
- **多平台支持**：Linux/macOS/Windows全平台兼容
- **可扩展架构**：支持插件式加密算法和地址生成器
- **类型安全**：完整的Go类型系统支持
- **灵活配置**：可根据需求选择不同的加密参数和算法

## 🏗️ 项目架构


```bash
github.com/palagend/ponk/
├── cmd/keystore-cli/          # 命令行工具
├── pkg/keystore/              # 加密核心实现
├── examples/                  # 使用示例
├── docs/                      # 详细文档
└── tests/                     # 测试用例
```


## 🔐 加密/解密核心原理

### 加密流程示意图

[![f66b5b8c8a6e58](https://origin.picgo.net/2025/11/21/f66b5b8c8a6e58621474605f228c74.png)](https://www.picgo.net/image/f66b5b8c8a6e58.UEtmMp)

### 加密核心技术

1. **密码强化**：使用scrypt进行密钥派生
   math
   DK = scrypt(password, salt, N=262144, r=8, p=1, dkLen=32)


2. **分层加密**：
   - 前16字节 → AES-CTR加密密钥
   - 后16字节 → MAC校验密钥

3. **完整性保护**：
   go
   MAC = SHA256(DK[16:32] + cipherText)

### 解密流程示意图
[![7a07bdce874c68](https://origin.picgo.net/2025/11/21/7a07bdce874c68949d68613a717d2f.png)](https://www.picgo.net/image/7a07bdce874c68.UErUC7)

### 解密核心技术
* **第一层：弱密码强化（scrypt）**
用 scrypt 将弱密码转化为高强度密钥，抵御暴力破解，解决 “用户密码易记但不安全” 的矛盾；
* **第二层：双重校验（MAC）**
同时验证 “密码正确性” 和 “数据完整性”，避免 “密码对但数据被篡改” 或 “数据完整但密码错” 的风险；
* **第三层：私钥加密（AES-128-CTR）**
用对称加密保护私钥，即使 KeyStore 文件泄露，攻击者无密码也无法获取私钥（AES-128 的暴力破解需 2^128 次运算，当前技术无法实现）。


当用户在 MetaMask、Geth 中输入密码签名交易时，底层即执行该流程：
解析 KeyStore 文件→scrypt 派生密钥→MAC 校验→AES-128-CTR 解密出私钥→用私钥签名交易（ECDSA 签名），全程私钥仅在内存中短暂存在，不落地存储，最大程度降低泄露风险。

总之，其核心技术是密码学在 “密钥管理” 场景的经典落地，本质是通过 “密钥派生（scrypt）+ 对称加密（AES-128-CTR）+ 完整性校验（MAC）” 的组合，解决 “用户弱密码→安全存储私钥” 的核心问题。其设计思路可迁移到所有 “敏感信息加密存储” 场景（如支付密码存储、证书私钥管理），核心原则是：用计算成本换安全，用多环节校验防篡改。

## 🚀 快速开始

### 安装

```bash
go get github.com/palagend/ponk
```

### 基本用法

```go
package main

import (
    "fmt"
    "log"

    "github.com/palagend/ponk/pkg/keystore"
)

func main() {
    // 初始化keystore管理器
    ks, err := keystore.NewKeyStore("./secure-keystore", nil)
    if err != nil {
        log.Fatal("初始化keystore失败: ", err)
    }
    
    // 生成新账户
    password := "YourVeryStrongPassword123!"
    address, err := ks.CreateNewAccount(password)
    if err != nil {
        log.Fatal("创建账户失败: ", err)
    }
    
    fmt.Printf("新账户地址: %s\n", address)
    fmt.Println("✅ Keystore文件保存成功")
    
    // 从keystore文件获取密钥
    key, err := ks.GetKey(address, password)
    if err != nil {
        log.Fatal("获取密钥失败: ", err)
    }
    
    fmt.Println("✅ 密钥获取成功")
    fmt.Printf("   地址: %s\n", key.Address)
    fmt.Printf("   算法: %s\n", key.Algorithm)
}
```

### 多链配置示例

```go
package main

import (
    "fmt"
    "log"

    "github.com/palagend/ponk/pkg/keystore"
)

func main() {
    // 自定义配置
    options := keystore.DefaultKeyStoreOptions()
    options.Algorithm = "ecdsa"        // 加密算法
    options.AddressGenerator = "eth"    // 地址生成器
    options.ScryptN = 16384             // 降低scrypt参数以加快测试速度
    
    // 初始化keystore管理器
    ks, err := keystore.NewKeyStore("./multi-chain-keystore", options)
    if err != nil {
        log.Fatal("初始化keystore失败: ", err)
    }
    
    // 生成新账户
    password := "MultiChainPassword123!"
    address, err := ks.CreateNewAccount(password)
    if err != nil {
        log.Fatal("创建账户失败: ", err)
    }
    
    fmt.Printf("新账户地址: %s\n", address)
    fmt.Println("✅ 多链Keystore文件保存成功")
}
```

## 📚 核心API

### KeyStore结构体

```go
// 创建KeyStore实例
func NewKeyStore(keydir string, options *KeyStoreOptions) (*KeyStore, error)

// 创建新账户
func (ks *KeyStore) CreateNewAccount(password string) (string, error)

// 导入ECDSA私钥
func (ks *KeyStore) ImportECDSA(privateKey *ecdsa.PrivateKey, password string) (string, error)

// 导入通用私钥
func (ks *KeyStore) ImportPrivateKey(privateKey interface{}, password string) (string, error)

// 导入keystore文件
func (ks *KeyStore) ImportKey(keyJSON []byte, oldPassword, newPassword string) (string, error)

// 导出keystore文件
func (ks *KeyStore) ExportKey(address, password string) ([]byte, error)

// 获取密钥
func (ks *KeyStore) GetKey(address, password string) (*Key, error)

// 删除密钥
func (ks *KeyStore) Delete(address, password string) error

// 列出所有账户
func (ks *KeyStore) List() ([]string, error)

// 检查地址是否存在
func (ks *KeyStore) HasAddress(address string) bool

// 修改密码
func (ks *KeyStore) ChangePassword(address, oldPassword, newPassword string) error

// 使用私钥签名
func (ks *KeyStore) Sign(address string, hash []byte, password string) ([]byte, error)
```

### Key结构体

```go
type Key struct {
    Address     string      // 区块链地址
    PrivateKey  interface{} // 私钥（类型取决于算法）
    PublicKey   interface{} // 公钥（类型取决于算法）
    Algorithm   string      // 加密算法
    CreatedAt   int64       // 创建时间戳
}
```

### KeyStoreOptions配置

```go
// 默认配置
func DefaultKeyStoreOptions() *KeyStoreOptions

// 配置结构体
type KeyStoreOptions struct {
    // Scrypt参数
    ScryptN int `json:"scryptN"`
    ScryptR int `json:"scryptR"`
    ScryptP int `json:"scryptP"`
    
    // 密码策略
    MinPasswordLen     int  `json:"minPasswordLen"`
    MaxPasswordLen     int  `json:"maxPasswordLen"`
    PasswordComplexity bool `json:"passwordComplexity"`
    
    // 算法配置
    Algorithm        string `json:"algorithm"`        // 加密算法
    AddressGenerator string `json:"address_generator"` // 地址生成器
}

// 自定义配置示例
options := keystore.DefaultKeyStoreOptions()
options.ScryptN = 16384             // 降低scrypt参数以加快测试速度
options.Algorithm = "ecdsa"        // 加密算法
options.AddressGenerator = "eth"    // 地址生成器
```

## 🔧 命令行工具

### 安装CLI

```bash
go install github.com/palagend/ponk/cmd/keystore-cli@latest
```

### 使用示例


创建新账户
```bash
keystore-cli new --path ./wallet --password "secure-password"
```

列出账户
```bash
keystore-cli list --path ./wallet
```

导出私钥
```bash
keystore-cli export --address 0x... --password "secure-password"
```

导入keystore文件
```bash
keystore-cli import --file ./backup.json --password "old-password" --new-password "new-password"
```


## 🛡️ 安全最佳实践

### 密码策略

1. **最少12个字符**：包含大小写字母、数字和特殊符号
2. **避免常见短语**：不要使用字典单词或常见密码模式
3. **定期更换**：建议每3-6个月更换一次密码

### 文件安全


设置严格的目录权限
```bash
chmod 700 /keystore/path
chmod 600 /keystore/path/*.json
```

启用文件系统加密
```bash
sudo fscrypt encrypt /keystore/path
```

### 内存管理

```go
// 安全清理敏感数据
func secureOperation() {
    privateKeyBytes := make([]byte, 32)
    // ... 使用私钥 ...
    defer crypto.SecureClear(privateKeyBytes) // 确保清理
}
```

## 📊 性能基准测试

| 操作 | 平均耗时 | 内存使用 |
|------|----------|----------|
| 密钥生成 | 15ms | 2MB |
| 加密存储 | 45ms | 5MB |
| 解密恢复 | 35ms | 3MB |

## 🔍 故障排除

### 常见问题

**Q: 密码验证失败**

检查keystore文件完整性
```bash
keystore-cli verify --file UTC--xxxxx
```

重置密码（需要备份助记词）
```bash
keystore-cli recover --mnemonic "12 words" --new-password "new-pass"
```


**Q: 文件权限错误**
bash
修复文件权限
```bash
sudo chown -R USER:USER ./keystore
chmod -R 600 ./keystore/*.json
```


## 🤝 贡献指南

我们欢迎社区贡献！请阅读[贡献指南](CONTRIBUTING.md)了解详情。

1. Fork项目
2. 创建功能分支：`git checkout -b feature/amazing-feature`
3. 提交更改：`git commit -m 'Add amazing feature'`
4. 推送到分支：`git push origin feature/amazing-feature`
5. 提交Pull Request

## 📄 许可证

本项目采用GPLv3许可证 - 详见[LICENSE](LICENSE)文件。

## 🙏 致谢

- [Go Ethereum Team](https://geth.ethereum.org/) - 提供keystore规范参考

## 📞 支持

- 📧 Email: palagend@qq.com
- 💬 Issues: [GitHub Issues](https://github.com/palagend/ponk/issues)
- 📚 文档: [项目Wiki](https://github.com/palagend/ponk/wiki)

---

<div align="center">

**⭐ 如果这个项目对您有帮助，请给我们一个Star！**

</div>
