package main

import (
	"bytes"
	"crypto"
	"crypto/cipher"
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

// ====== 常量定义 ======
const (
	DES_KEY = "88T3j05dtFu8="

	RSA_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
		"xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
		"NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----"

	BDINFO_LEN        = 0xde96
	BDINFO_DATA_LEN   = 0xdd80
	BDINFO_DEC_LEN    = 0xdd7c
	BDINFO_RSA_OFFSET = 0xdd80
	BDINFO_RSA_LEN    = 0x80
	BDINFO_END_MAGIC  = "BDINFO_END"
)

func main() {
	inputFile := flag.String("i", "", "输入的加密 bdinfo 文件路径 (必填)")
	outputFile := flag.String("o", "", "将解密后的原始明文导出到指定文件")
	targetKey := flag.String("k", "", "仅获取并打印指定键(Key)的值")
	skipRsa := flag.Bool("r", false, "跳过 RSA 签名完整性校验")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s -i <输入文件> [-o <输出文件>] [-k <配置项Key>] [-r]\n", os.Args)
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

	bdinfoEncrypted, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法读取输入文件: %v\n", err)
		os.Exit(1)
	}

	if len(bdinfoEncrypted) != BDINFO_LEN {
		fmt.Fprintf(os.Stderr, "错误: 读取的字节数 (%d) 与预期大小 (%d) 不符。\n", len(bdinfoEncrypted), BDINFO_LEN)
		os.Exit(1)
	}

	if !*skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintf(os.Stderr, "错误: RSA 数字签名校验失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 56700 不是 8 的倍数，原 C 代码实际上抛弃了末尾无法成块的 4 字节
	alignedLen := (BDINFO_DEC_LEN / 8) * 8

	cipherText := bdinfoEncrypted[4 : 4+alignedLen]
	bdinfoDecrypted, err := decryptDesCbc(cipherText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: DES 解密失败: %v\n", err)
		os.Exit(1)
	}

	if *outputFile != "" {
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput, bdinfoDecrypted)
		err = os.WriteFile(*outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 写入输出文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("成功将解密数据导出至: %s\n", *outputFile)
	} else {
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 解析 bdinfo 文本失败: %v\n", err)
			os.Exit(1)
		}

		printBdinfo(bdinfoValues, *targetKey)
	}
}

func validateBdinfoMd5(input []byte) error {
	rsaSignature := input[BDINFO_RSA_OFFSET : BDINFO_RSA_OFFSET+BDINFO_RSA_LEN]
	dataToVerify := input[0:BDINFO_DATA_LEN]

	hasher := md5.New()
	hasher.Write(dataToVerify)
	md5Digest := hasher.Sum(nil)

	block, _ := pem.Decode([]byte(RSA_KEY))
	if block == nil {
		return fmt.Errorf("无法解析公钥 PEM 块")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("无法解析 PKCS#1 RSA 公钥: %v", err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.MD5, md5Digest, rsaSignature)
	if err != nil {
		return fmt.Errorf("签名验证未通过（数据可能已被篡改）")
	}

	return nil
}

// 模拟 OpenSSL 的 DES_string_to_key 核心算法
func opensslStringToKey(str string) []byte {
	key := make([]byte, 8)
	strBytes := []byte(str)

	// OpenSSL 经典映射：异或移位叠加
	for i := 0; i < len(strBytes); i++ {
		j := i % 8
		if (i / 8) % 2 == 1 {
			// 奇数个 8 字节块，逆序映射并移位
			key[7-j] ^= (strBytes[i] << 1)
		} else {
			// 偶数个 8 字节块，正序映射并移位
			key[j] ^= (strBytes[i] << 1)
		}
	}

	// 强行修正奇偶校验位 (DES 密钥每字节最低位为校验位)
	for i := 0; i < 8; i++ {
		b := key[i]
		// 计算前 7 位的 1 的个数
		count := 0
		for bit := 1; bit < 256; bit <<= 1 {
			if b&byte(bit) != 0 {
				count++
			}
		}
		// 如果 1 的个数是偶数，将最低位置 1，凑成奇数个 1
		if count%2 == 0 {
			key[i] |= 1
		} else {
			key[i] &= 0xFE
		}
	}

	return key
}

func decryptDesCbc(cipherText []byte) ([]byte, error) {
	// 使用完美的 OpenSSL 密钥平替函数
	keyBytes := opensslStringToKey(DES_KEY)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	ivBytes := make([]byte, des.BlockSize)
	mode := NewCBCDecrypter(block, ivBytes)

	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	return decrypted, nil
}

func parseBdinfo(data []byte) (map[string]string, error) {
	// 移除可能存在的无效前导或尾部非文本空字节
	text := string(bytes.Trim(data, "\x00"))

	eofIndex := strings.Index(text, BDINFO_END_MAGIC)
	if eofIndex == -1 {
		return nil, fmt.Errorf("未找到 EOF 结束标记 (BDINFO_END)")
	}

	validText := text[:eofIndex]
	lines := strings.Split(validText, "\n")
	bdinfoValues := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		sepIndex := strings.Index(line, "=")
		if sepIndex == -1 {
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

// ====== 补全 Go 标准库缺失的传统 CBC 解密接口 ======
type cbcDecrypter struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
}

func NewCBCDecrypter(b cipher.Block, iv []byte) *cbcDecrypter {
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
		copy(x.tmp, src[:x.blockSize])
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])

		for i := 0; i < x.blockSize; i++ {
			dst[i] ^= x.iv[i]
		}

		copy(x.iv, x.tmp)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
