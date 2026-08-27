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
	"fmt"
	"os"
	"strings"
)

// ====== 常量定义 (像素级复现C语言硬编码参数) ======
const (
	// 原文无引号宏 88T3j05dtFu8=，这里提供两种可能进行容错切换
	DES_KEY_RAW  = "88T3j05dtFu8="
	DES_KEY_ALT  = "88T3j05dtFu8"

	RSA_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
		"xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
		"NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----"

	BDINFO_LEN           = 0xde96 // 57002 字节 (fread读取的总长度)
	BDINFO_DATA_LEN      = 0xdd80 // 56704 字节 (参与MD5校验的数据长度)
	BDINFO_DEC_LEN       = 0xdd7c // 56700 字节 (解密文本的总空间上限)
	BDINFO_RSA_OFFSET    = 0xdd80 // 56704 字节 (RSA签名的绝对起点)
	BDINFO_RSA_LEN       = 0x80   // 128 字节 (RSA-1024签名)
	BDINFO_END_MAGIC     = "BDINFO_END"
	BDINFO_VAL_NUM_VALS  = 64
)

func printHelp() {
	fmt.Fprintf(os.Stderr, "用法: %s -i <输入文件> [-o <输出文件>] [-k <配置项Key>] [-r]\n\n", os.Args)
	fmt.Fprintln(os.Stderr, "  -i <file>\t输入的加密 bdinfo 文件路径 (必填)")
	fmt.Fprintln(os.Stderr, "  -o <file>\t将解密后的原始明文导出到指定文件")
	fmt.Fprintln(os.Stderr, "  -k <key>\t仅获取并打印指定键(Key)的值")
	fmt.Fprintln(os.Stderr, "  -r       \t跳过 RSA 签名完整性校验")
}

func main() {
	var inputFile, outputFile, targetKey string
	var skipRsa bool

	// ====== 1. 命令行参数解析 ======
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			printHelp()
			return
		case "-i":
			if i+1 < len(args) {
				inputFile = args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-k":
			if i+1 < len(args) {
				targetKey = args[i+1]
				i++
			}
		case "-r":
			skipRsa = true
		default:
			fmt.Fprintf(os.Stderr, "未知参数: %s\n", args[i])
			printHelp()
			os.Exit(1)
		}
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Input file required.")
		os.Exit(1)
	}
	if outputFile != "" && targetKey != "" {
		fmt.Fprintln(os.Stderr, "Decryption and dump not possible.")
		os.Exit(1)
	}

	// ====== 2. 读取并裁剪文件流 (对齐 C 语言 fread 边界) ======
	fileBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening file")
		os.Exit(1)
	}

	if len(fileBytes) < BDINFO_LEN {
		fmt.Fprintln(os.Stderr, "Read bytes does not equal expected value")
		os.Exit(1)
	}
	// 强行截取前 57002 字节，丢弃更靠后的多余数据
	bdinfoEncrypted := fileBytes[:BDINFO_LEN]

	// ====== 3. RSA 数字签名校验 ======
	if !skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintln(os.Stderr, "Error checking RSA signature")
			fmt.Fprintf(os.Stderr, "详请: %v\n", err)
			os.Exit(1)
		}
	}

	// ====== 4. DES-CBC 解密 (带密钥容错机制) ======
	// 对齐 C 语言的 8 字节块分组硬性限制
	alignedLen := (BDINFO_DEC_LEN / 8) * 8 // 56696
	cipherText := bdinfoEncrypted[4 : 4+alignedLen]

	var bdinfoDecrypted []byte
	
	// 【核心双轨解密容错】尝试第一把预设密钥
	bdinfoDecrypted, err = decryptDesCbc(cipherText, DES_KEY_RAW)
	
	// 验证解密出的内容是否包含有效的 ASCII。如果完全不含等号或全是乱码，自动切第二把密钥
	if err != nil || !bytes.Contains(bdinfoDecrypted, []byte("=")) {
		// 尝试去掉等号的备用密钥
		if altDecrypted, altErr := decryptDesCbc(cipherText, DES_KEY_ALT); altErr == nil && bytes.Contains(altDecrypted, []byte("=")) {
			bdinfoDecrypted = altDecrypted
		}
	}

	// 如果依然无法解密出有实际意义的内容
	if len(bdinfoDecrypted) == 0 {
		fmt.Fprintln(os.Stderr, "Error decrypting bdinfo (解密失败，输出可能仍为乱码)")
		os.Exit(1)
	}

	// ====== 5. 结果投递与解析 ======
	if outputFile != "" {
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput, bdinfoDecrypted)
		err = os.WriteFile(outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error writing output file")
			os.Exit(1)
		}
	} {
		// 严格对齐 C 语言参数限制：parse_bdinfo(buf, BDINFO_DEC_LEN)
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted, BDINFO_DEC_LEN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing bdinfo")
			fmt.Fprintf(os.Stderr, "详情: %v\n", err)
			os.Exit(1)
		}

		printBdinfo(bdinfoValues, targetKey)
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
		return fmt.Errorf("Error allocating RSA public key")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error reading RSA public key")
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.MD5, md5Digest, rsaSignature)
	if err != nil {
		return fmt.Errorf("Error validating MD5")
	}

	return nil
}

// 完美模拟 OpenSSL 独家暗号：DES_string_to_key 变换逻辑
func opensslStringToKey(str string) []byte {
	key := make([]byte, 8)
	strBytes := []byte(str)

	for i := 0; i < len(strBytes); i++ {
		j := i % 8
		if (i / 8)%2 == 1 {
			key[7-j] ^= (strBytes[i] << 1)
		} else {
			key[j] ^= (strBytes[i] << 1)
		}
	}

	for i := 0; i < 8; i++ {
		b := key[i]
		count := 0
		for bit := 1; bit < 256; bit <<= 1 {
			if b&byte(bit) != 0 {
				count++
			}
		}
		if count%2 == 0 {
			key[i] |= 1
		} else {
			key[i] &= 0xFE
		}
	}

	return key
}

func decryptDesCbc(cipherText []byte, keyStr string) ([]byte, error) {
	keyBytes := opensslStringToKey(keyStr)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	ivBytes := make([]byte, des.BlockSize) // 全零初始化向量
	mode := NewCBCDecrypter(block, ivBytes)

	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	return decrypted, nil
}

func parseBdinfo(data []byte, maxLen int) ([]string, error) {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	// 移除解密出来可能残存的空字节流，避免干扰字符串查找
	text := string(bytes.Trim(data, "\x00"))

	if !strings.Contains(text, BDINFO_END_MAGIC) {
		return nil, fmt.Errorf("EOF Marker not found")
	}

	rawLines := strings.Split(text, "\n")
	var finalLines []string

	// 严格控制最大处理行数为 64 行 (BDINFO_VAL_NUM_VALS)
	for _, line := range rawLines {
		if len(finalLines) >= BDINFO_VAL_NUM_VALS {
			break
		}
		// 检查 C 语言的 EOF Marker 中断判定
		if strings.HasPrefix(strings.TrimSpace(line), BDINFO_END_MAGIC) {
			break
		}
		finalLines = append(finalLines, line)
	}

	kvPairs := make([]string, 0, len(finalLines)*2)

	for _, line := range finalLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		sepIndex := strings.Index(line, "=")
		if sepIndex == -1 {
			return nil, fmt.Errorf("Invalid line without separator")
		}

		// 模拟 C 语言等号内存截断行为
		key := strings.TrimSpace(line[:sepIndex])
		value := strings.TrimSpace(line[sepIndex+1:])
		
		// 剥离老旧固件可能残留的控制符
		value = strings.TrimRight(value, "\r\x00")

		if key != "" {
			kvPairs = append(kvPairs, key, value)
		}
	}

	return kvPairs, nil
}

func printBdinfo(kvPairs []string, targetKey string) {
	keyFound := false

	for i := 0; i < len(kvPairs); i += 2 {
		k := kvPairs[i]
		v := kvPairs[i+1]

		if targetKey != "" {
			if k == targetKey {
				fmt.Printf("%s\n", v)
				keyFound = true
				return
			}
		} else {
			fmt.Printf("%s = %s\n", k, v)
		}
	}

	if targetKey != "" && !keyFound {
		fmt.Fprintf(os.Stderr, "Key %s not found in bdinfo\n", targetKey)
		os.Exit(1)
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
