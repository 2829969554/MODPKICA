# go-cryptobin

go-cryptobin 是一个 Go 语言的加密解密库，支持多种加密/解密方式以及签名/验证操作。

## 功能简介

*  支持加密/解密、签名/验证等常用功能
*  支持多种加密算法，包括对称加密和非对称加密
*  提供简单易用的 API 接口

## 安装

使用以下命令安装：

```bash
go get -u github.com/go-cryptobin/go-cryptobin
```

## 使用方法

### 加密与解密

使用 `Encrypt()` 和 `Decrypt()` 方法进行加密和解密操作：

```go
import "github.com/go-cryptobin/cryptobin"

encrypted := cryptobin.Encrypt([]byte("your-data"), []byte("your-key"))
decrypted := cryptobin.Decrypt(encrypted, []byte("your-key"))
```

### 签名与验证

使用 `Sign()` 和 `Verify()` 方法进行签名和验证：

```go
signature := cryptobin.Sign([]byte("your-data"), []byte("your-private-key"))
isVerified := cryptobin.Verify([]byte("your-data"), signature, []byte("your-public-key"))
```

## 数据类型转换

支持将加密或解密后的数据转换为以下格式：

*  字节切片 `ToBytes()`
*  字符串 `ToString()`
*  Base64 编码字符串 `ToBase64String()`
*  十六进制字符串 `ToHexString()`

## 文档

更多详细信息，请查看 [文档](docs/README.md)。

## 开源协议

本项目遵循 `Apache2` 协议发布，使用时请保留相关版权信息。