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

// ====== 常量定义 (严格对齐C语言) ======
const (
	DES_KEY = "88T3j05dtFu8="

	RSA_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
		"xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
		"NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----"

	BDINFO_LEN           = 0xde96 // 57002
	BDINFO_DATA_LEN      = 0xdd80 // 56704
	BDINFO_DEC_LEN       = 0xdd7c // 56700
	BDINFO_RSA_OFFSET    = 0xdd80
	BDINFO_RSA_LEN       = 0x80
	BDINFO_END_MAGIC     = "BDINFO_END"
	BDINFO_VAL_NUM_VALS  = 64 // 👈 严格限制解析行数最大为 64
)

func printHelp() {
	fmt.Fprintf(os.Stderr, "用法: %s -i <输入文件> [-o <输出文件>] [-k <配置项Key>] [-r]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  -i <file>\t输入的加密 bdinfo 文件路径 (必填)")
	fmt.Fprintln(os.Stderr, "  -o <file>\t将解密后的原始明文导出到指定文件")
	fmt.Fprintln(os.Stderr, "  -k <key>\t仅获取并打印指定键(Key)的值")
	fmt.Fprintln(os.Stderr, "  -r       \t跳过 RSA 签名完整性校验")
}

func main() {
	var inputFile, outputFile, targetKey string
	var skipRsa bool

	// ====== 1. 命令行参数解析 (完全对齐 C 的 getopt 逻辑) ======
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
		fmt.Fprintln(os.Stderr, "Input file required.") // 👈 对齐 C 语言原始报错提示
		os.Exit(1)
	}
	if outputFile != "" && targetKey != "" {
		fmt.Fprintln(os.Stderr, "Decryption and dump not possible.") // 👈 对齐 C 语言原始报错提示
		os.Exit(1)
	}

	// ====== 2. 读取文件 (完全对齐 C 语言 fread 逻辑) ======
	fileBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening file") // 👈 对齐 C 语言原始报错提示
		os.Exit(1)
	}

	// C 语言固定读取 BDINFO_LEN，不够或超载都报错
	if len(fileBytes) < BDINFO_LEN {
		fmt.Fprintln(os.Stderr, "Read bytes does not equal expected value")
		os.Exit(1)
	}
	bdinfoEncrypted := fileBytes[:BDINFO_LEN]

	// ====== 3. RSA 完整性校验 ======
	if !skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintln(os.Stderr, "Error checking RSA signature")
			os.Exit(1)
		}
	}

	// ====== 4. DES-CBC 解密 ======
	// C 语言传入长度为 BDINFO_DEC_LEN (56700)，但 DES 必须对齐 8 字节块
	// C 语言底层抛弃了最后无法成块的 4 字节，这里向下对齐到 56696
	alignedLen := (BDINFO_DEC_LEN / 8) * 8

	// 对齐 C 语言的 decrypt(bdinfo_encrypted + 4, ...)
	cipherText := bdinfoEncrypted[4 : 4+alignedLen]
	bdinfoDecrypted, err := decryptDesCbc(cipherText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decrypting bdinfo")
		os.Exit(1)
	}

	// ====== 5. 输出分支 ======
	if outputFile != "" {
		// C 语言写入长度为整个明文缓冲区的预设大小 BDINFO_LEN (57002)
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput, bdinfoDecrypted)
		
		err = os.WriteFile(outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error writing output file")
			os.Exit(1)
		}
	} else {
		// 对齐 C 语言的 parse_bdinfo(bdinfo_decrypted, BDINFO_DEC_LEN)
		// 传入解密区段的最大允许截断长度
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted, BDINFO_DEC_LEN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing bdinfo")
			os.Exit(1)
		}

		printBdinfo(bdinfoValues, targetKey)
	}
}

// 验证 RSA 数字签名
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

// 模拟 OpenSSL 专属的 DES_string_to_key 映射流
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

// DES-CBC 解密
func decryptDesCbc(cipherText []byte) ([]byte, error) {
	keyBytes := opensslStringToKey(DES_KEY)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	ivBytes := make([]byte, des.BlockSize) // 全 0 IV
	mode := NewCBCDecrypter(block, ivBytes)

	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	return decrypted, nil
}

// 解析文本 (像素级复现 C 语言的 strsep / strstr 破坏性切分行为)
func parseBdinfo(data []byte, maxLen int) ([]string, error) {
	// 截取到最大允许解析长度
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	text := string(data)

	// 1. C 语言首先在整个大缓冲区检索 "BDINFO_END" 是否存在
	if !strings.Contains(text, BDINFO_END_MAGIC) {
		return nil, fmt.Errorf("EOF Marker not found")
	}

	// 2. 按 "\n" 切分行 (模拟 strsep)
	rawLines := strings.Split(text, "\n")
	
	// 存储行数据，严格限制容量为 64 (BDINFO_VAL_NUM_VALS)
	var finalLines []string

	for _, line := range rawLines {
		if len(finalLines) >= BDINFO_VAL_NUM_VALS {
			break
		}
		// C 语言行为：如果某一行是以 "BDINFO_END" 开头，则认为解析该结束，且此行不计入数组
		if strings.HasPrefix(line, BDINFO_END_MAGIC) {
			break
		}
		finalLines = append(finalLines, line)
	}

	// 3. 解析所有的键值对
	// 结构体内映射：[0] 为 key, [1] 为 value。因为可能存在同名 key，C 用数组遍历，Go 这里用切片保持先后顺序
	kvPairs := make([]string, 0, len(finalLines)*2)

	for _, line := range finalLines {
		// 寻找 "=" 号分隔符
		sepIndex := strings.Index(line, "=")
		if sepIndex == -1 {
			return nil, fmt.Errorf("Invalid line without separator")
		}

		// 👈 核心像素级同步：C 语言找到第一个等号后会将其强行置 0 (\0)。
		// 意味着 key 是等号前面的部分，value 是等号后面直到行尾（或者直到下一个 \0，也就是被 \r 截断）
		key := line[:sepIndex]
		value := line[sepIndex+1:]

		// 清理 C 语言在行尾遗留的 Windows 换行符 \r
		value = strings.TrimRight(value, "\r")

		kvPairs = append(kvPairs, key, value)
	}

	return kvPairs, nil
}

// 打印解析结果 (完美对应 C 语言的动态遍历查找)
func printBdinfo(kvPairs []string, targetKey string) {
	keyFound := false

	for i := 0; i < len(kvPairs); i += 2 {
		k := kvPairs[i]
		v := kvPairs[i+1]

		if targetKey != "" {
			if k == targetKey {
				fmt.Printf("%s\n", v) // 👈 对齐 C 语言：printf("%s\n", bdval->value)
				keyFound = true
				return
			}
		} else {
			fmt.Printf("%s = %s\n", k, v) // 👈 对齐 C 语言格式化输出
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
