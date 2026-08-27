package main

import (
	"bytes"
	"crypto"
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ====== 常量定义 (已修正原C代码中的语法错误) ======
const (
	DES_KEY = "88T3j05dtFu8="

	RSA_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
		"xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
		"NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----"

	BDINFO_LEN        = 0xde96 // 57002 字节
	BDINFO_DATA_LEN   = 0xdd80 // 56704 字节
	BDINFO_DEC_LEN    = 0xdd7c // 56700 字节
	BDINFO_RSA_OFFSET = 0xdd80 // RSA签名偏移
	BDINFO_RSA_LEN    = 0x80   // 128 字节 (RSA-1024)
	BDINFO_END_MAGIC  = "BDINFO_END"
)

func main() {
	// ====== 1. 解析命令行参数 (使用 Go 标准库 flag) ======
	inputFile := flag.String("i", "", "输入的加密 bdinfo 文件路径 (必填)")
	outputFile := flag.String("o", "", "将解密后的原始明文导出到指定文件")
	targetKey := flag.String("k", "", "仅获取并打印指定键(Key)的值")
	skipRsa := flag.Bool("r", false, "跳过 RSA 签名完整性校验")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s -i <输入文件> [-o <输出文件>] [-k <配置项Key>] [-r]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须指定输入文件 (-i)。")
		flag.Usage()
		os.Exit(1)
	}
	if *outputFile != "" && *targetKey != "" {
		fmt.Fprintln(os.Stderr, "错误: 不能同时指定解密导出 (-o) 和 查询Key (-k)。")
		os.Exit(1)
	}

	// ====== 2. 读取输入文件 ======
	bdinfoEncrypted, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法读取输入文件: %v\n", err)
		os.Exit(1)
	}

	if len(bdinfoEncrypted) != BDINFO_LEN {
		fmt.Fprintf(os.Stderr, "错误: 读取的字节数 (%d) 与预期大小 (%d) 不符。\n", len(bdinfoEncrypted), BDINFO_LEN)
		os.Exit(1)
	}

	// ====== 3. 验证 RSA 数字签名 (MD5) ======
	if !*skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintf(os.Stderr, "错误: RSA 数字签名校验失败: %v\n", err)
			os.Exit(1)
		}
	}

	// ====== 4. DES-CBC 解密 ======
	// C 代码中写的是 bdinfo_encrypted + 4，这里截取从索引 4 开始、长度为 BDINFO_DEC_LEN 的切片
	cipherText := bdinfoEncrypted[4 : 4+BDINFO_DEC_LEN]
	bdinfoDecrypted, err := decryptDesCbc(cipherText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: DES 解密失败: %v\n", err)
		os.Exit(1)
	}

	// ====== 5. 输出处理 ======
	if *outputFile != "" {
		// 保持与 C 语言写入原大小 BDINFO_LEN 的逻辑一致
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput, bdinfoDecrypted)
		err = os.WriteFile(*outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 写入输出文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("成功将解密数据导出至: %s\n", *outputFile)
	} else {
		// 解析并打印
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 解析 bdinfo 文本失败: %v\n", err)
			os.Exit(1)
		}

		printBdinfo(bdinfoValues, *targetKey)
	}
}

// 验证 RSA 数字签名与数据 MD5 是否一致
func validateBdinfoMd5(input []byte) error {
	// 1. 提取签名数据
	rsaSignature := input[BDINFO_RSA_OFFSET : BDINFO_RSA_OFFSET+BDINFO_RSA_LEN]

	// 2. 计算前 BDINFO_DATA_LEN 字节数据的 MD5 摘要
	dataToVerify := input[0:BDINFO_DATA_LEN]
	hasher := md5.New()
	hasher.Write(dataToVerify)
	md5Digest := hasher.Sum(nil)

	// 3. 解析 PEM 格式的 RSA 公钥
	block, _ := pem.Decode([]byte(RSA_KEY))
	if block == nil {
		return fmt.Errorf("无法解析公钥 PEM 块")
	}

	// 原 C 代码使用的是 PEM_read_bio_RSAPublicKey (PKCS#1 格式)
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("无法解析 PKCS#1 RSA 公钥: %v", err)
	}

	// 4. 验证签名。原 C 使用 RSA_public_decrypt（相当于底层直接比对解密后的哈希）
	// Go 语言使用标准安全的 rsa.VerifyPKCS1v15 来做平替验证
	err = rsa.VerifyPKCS1v15(pubKey, crypto.MD5, md5Digest, rsaSignature)
	if err != nil {
		return fmt.Errorf("签名验证未通过（数据可能已被篡改）")
	}

	return nil
}

// DES-CBC 解密
func decryptDesCbc(cipherText []byte) ([]byte, error) {
	// 原 C 语言使用 DES_string_to_key，它会对字符串截取生成 8 字节密钥。
	// 这里默认提取前 8 个字节（"88T3j05d"）作为标准平替
	keyBytes := []byte(DES_KEY[:8])

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	// 原 C 代码中 ivec 初始化为全 0
	ivBytes := make([]byte, des.BlockSize)

	// Go 标准库的 CBC 解密器
	mode := NewCBCDecrypter(block, ivBytes)

	// 创建输出缓冲区并执行解密
	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	return decrypted, nil
}

// 解析解密后的文本行并转为 Map
func parseBdinfo(data []byte) (map[string]string, error) {
	text := string(data)

	// 查找结束标记 BDINFO_END
	eofIndex := strings.Index(text, BDINFO_END_MAGIC)
	if eofIndex == -1 {
		return nil, fmt.Errorf("未找到 EOF 结束标记 (BDINFO_END)")
	}

	// 截取到结束标记前的有效内容
	validText := text[:eofIndex]
	lines := strings.Split(validText, "\n")
	bdinfoValues := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 查找等号分隔符
		sepIndex := strings.Index(line, "=")
		if sepIndex == -1 {
			// 类似 C 语言，跳过或提示无效行
			continue
		}

		key := strings.TrimSpace(line[:sepIndex])
		value := strings.TrimSpace(line[sepIndex+1:])

		if key != "" {
			bdinfoValues[key] = value
		}
	}

	return bdinfoValues, nil
}

// 打印解析结果
func printBdinfo(bdinfoValues map[string]string, targetKey string) {
	if targetKey != "" {
		if val, ok := bdinfoValues[targetKey]; ok {
			fmt.Println(val)
		} else {
			fmt.Fprintf(os.Stderr, "错误: 在 bdinfo 中未找到键 '%s'\n", targetKey)
		}
	} else {
		for k, v := range bdinfoValues {
			fmt.Printf("%s = %s\n", k, v)
		}
	}
}

// ====== 补全 Go 标准库缺失的传统 CBC 解密接口（Go 仅自带了 BlockMode 接口） ======
type cbcDecrypter struct {
	b         des.Block
	blockSize int
	iv        []byte
	tmp       []byte
}

func NewCBCDecrypter(b des.Block, iv []byte) *cbcDecrypter {
	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		tmp:       make([]byte, b.BlockSize()),
	}
}

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		// 先将当前密文块存入临时变量，因为解密后 src 内容可能会被 dst 覆写（如果是原位解密）
		copy(x.tmp, src[:x.blockSize])

		// 解密当前块
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])

		// 与前一个密文块（即 IV）进行异或
		for i := 0; i < x.blockSize; i++ {
			dst[i] ^= x.iv[i]
		}

		// 将当前密文块作为下一个块的 IV
		copy(x.iv, x.tmp)

		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
