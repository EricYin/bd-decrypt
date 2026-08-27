package main

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// ====== 常量定义 (严格遵照官方 Specification 规范) ======
const (
	DES_KEY_RAW = "88T3j05dtFu8="
	DES_KEY_ALT = "88T3j05dtFu8"

	RSA_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
		"xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
		"NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----"

	BDINFO_LEN        = 0xde96 // 57002 字节 (包含末尾挂载区)
	BDINFO_DATA_LEN   = 0xdd80 // 56704 字节 (VERSION 4字节 + DATA 56700字节)
	BDINFO_DEC_LEN    = 0xdd7c // 56700 字节 (DATA 密文区大小)
	BDINFO_RSA_OFFSET = 0xdd80 // 56704 字节 (RSA 签名起点)
	BDINFO_RSA_LEN    = 0x80   // 128 字节 (RSA-1024 签名大小)
	BDINFO_MAC_OFFSET = 0xde00 // 56832 字节 (RSA 结束，MAC 硬件明文区起点)
	BDINFO_VAL_NUM_VALS = 64
	BDINFO_END_MAGIC  = "BDINFO_END"
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

	// ====== 1. 命令行参数安全解析 ======
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

	// ====== 2. 读取并拆解物理文件 ======
	fileBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening file")
		os.Exit(1)
	}

	if len(fileBytes) < BDINFO_LEN {
		fmt.Fprintln(os.Stderr, "Read bytes does not equal expected value")
		os.Exit(1)
	}
	bdinfoEncrypted := fileBytes[:BDINFO_LEN]

	// 💡 【自检核心】根据规约验证大端序 Version
	versionBytes := bdinfoEncrypted[0:4]
	versionNum := binary.BigEndian.Uint32(versionBytes)
	if versionNum != 1 {
		fmt.Fprintf(os.Stderr, "警告: 规约目前仅支持 Version 1，当前文件解析出的版本号为: %d，可能会导致解析异常。\n", versionNum)
	}

	// 提取尾部明文硬件块
	macBytes := bdinfoEncrypted[BDINFO_MAC_OFFSET:]

	// ====== 3. RSA 数字签名验证 ======
	if !skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintln(os.Stderr, "Error checking RSA signature")
			os.Exit(1)
		}
	}

	// ====== 4. DATA 密文区解密 (自适应 CBC 变换) ======
	// 56700 向下做 8 字节块对齐，结果为 56696。
	alignedLen := (BDINFO_DEC_LEN / 8) * 8 
	cipherText := bdinfoEncrypted[4 : 4+alignedLen]

	var bdinfoDecrypted []byte
	keysToTry := []string{DES_KEY_RAW, DES_KEY_ALT}
	
	// 针对可能存在的 Enc/Dec 参数反转进行双向穷举
	for _, mode := range []string{"DECRYPT", "ENCRYPT"} {
		for _, kStr := range keysToTry {
			var res []byte
			var dErr error
			if mode == "DECRYPT" {
				res, dErr = cryptoDesCbc(cipherText, kStr, false)
			} else {
				res, dErr = cryptoDesCbc(cipherText, kStr, true)
			}

			// 只要解密流中包含规约里硬性要求的逻辑终点 "BDINFO_END"，即宣告破解成功！
			if dErr == nil && bytes.Contains(res, []byte(BDINFO_END_MAGIC)) {
				bdinfoDecrypted = res
				break
			}
		}
		if len(bdinfoDecrypted) > 0 {
			break
		}
	}

	if len(bdinfoDecrypted) == 0 {
		fmt.Fprintln(os.Stderr, "Error decrypting bdinfo (在 Data 密文解密区未搜寻到 BDINFO_END 标记)")
		os.Exit(1)
	}

	// ====== 5. 格式化输出与包合成 ======
	if outputFile != "" {
		// 构建导出文件：无损拼接
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput[0:4], versionBytes)
		copy(finalOutput[4:], bdinfoDecrypted)
		copy(finalOutput[BDINFO_MAC_OFFSET:], macBytes)
		
		err = os.WriteFile(outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error writing output file")
			os.Exit(1)
		}
		fmt.Printf("成功将明文固件包导出至: %s\n", outputFile)
	} else {
		// 控制台文本流键值对解析
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted, BDINFO_DEC_LEN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing bdinfo")
			os.Exit(1)
		}

		// 将版本号压入字典顶部
		bdinfoValues = append([]string{"BDINFO_VERSION", fmt.Sprintf("%d", versionNum)}, bdinfoValues...)

		// 将尾部硬件区信息压入字典底部
		macStr := string(bytes.Trim(macBytes, "\x00\r\n "))
		if macStr != "" {
			macLines := strings.Split(macStr, "\n")
			for _, mLine := range macLines {
				mLine = strings.TrimSpace(mLine)
				if strings.Contains(mLine, "=") {
					parts := strings.SplitN(mLine, "=", 2)
					bdinfoValues = append(bdinfoValues, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				} else if mLine != "" {
					bdinfoValues = append(bdinfoValues, "HARDWARE_EXTRA_INFO", mLine)
				}
			}
		}

		printBdinfo(bdinfoValues, targetKey)
	}
}

// 严格对齐规则：验证 VERSION + DATA 的 MD5 签名
func validateBdinfoMd5(input []byte) error {
	rsaSignature := input[BDINFO_RSA_OFFSET : BDINFO_RSA_OFFSET+BDINFO_RSA_LEN]
	// 刚好切出前 56704 字节 (即 4 字节 Version + 56700 字节 Data)
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

func cryptoDesCbc(cipherText []byte, keyStr string, isEncrypt bool) ([]byte, error) {
	keyBytes := opensslStringToKey(keyStr)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	ivBytes := make([]byte, des.BlockSize)
	var mode cipher.BlockMode
	
	if isEncrypt {
		mode = cipher.NewCBCEncrypter(block, ivBytes)
	} else {
		mode = NewCBCDecrypter(block, ivBytes)
	}

	out := make([]byte, len(cipherText))
	mode.CryptBlocks(out, cipherText)

	return out, nil
}

func parseBdinfo(data []byte, maxLen int) ([]string, error) {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	text := string(bytes.Trim(data, "\x00"))
	eofIndex := strings.Index(text, BDINFO_END_MAGIC)
	if eofIndex == -1 {
		return nil, fmt.Errorf("EOF Marker not found")
	}

	// 截取到 BDINFO_END 之前的内容
	validText := text[:eofIndex]
	rawLines := strings.Split(validText, "\n")
	var finalLines []string

	for _, line := range rawLines {
		if len(finalLines) >= BDINFO_VAL_NUM_VALS {
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

		key := strings.TrimSpace(line[:sepIndex])
		value := strings.TrimSpace(line[sepIndex+1:])
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

// ====== CBC 传统块级解密器结构体 ======
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
