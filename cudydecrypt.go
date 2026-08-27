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

// ====== 严格遵循 C 语言原版的常量定义 ======
const (
	DES_KEY = "88T3j05dtFu8="

	// 保持与 C 语言原始字面量完全相同的排版，包含所有的反斜杠和转义
	RSA_KEY = `-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEc wtDlwKDukESn5X+v8Bre\n\
xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n\
NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n\
-----END RSA PUBLIC KEY-----`

	BDINFO_LEN           = 0xde96 
	BDINFO_DATA_LEN      = 0xdd80 
	BDINFO_DEC_LEN       = 0xdd7c 
	BDINFO_RSA_OFFSET    = 0xdd80 
	BDINFO_RSA_LEN       = 0x80   
	BDINFO_VAL_NUM_VALS  = 64
	BDINFO_END_MAGIC     = "BDINFO_END"
)

func printHelp() {
	fmt.Fprintf(os.Stderr, "Usage: %s -i <input-file> [-o <output-file>] [-k <key>] [-r]\n\n", os.Args)
	fmt.Fprintln(os.Stderr, "\t-k <key>\tRetrieve value of key")
	fmt.Fprintln(os.Stderr, "\t-r\tSkip RSA signature check")
}

func main() {
	var inputFile, outputFile, targetKey string
	var skipRsa bool

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h":
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

	if !skipRsa {
		if err := validateBdinfoMd5(bdinfoEncrypted); err != nil {
			fmt.Fprintln(os.Stderr, "Error checking RSA signature")
			os.Exit(1)
		}
	}

	alignedLen := (BDINFO_DEC_LEN / 8) * 8 
	cipherText := bdinfoEncrypted[4 : 4+alignedLen]

	bdinfoDecrypted, err := decryptDesCbc(cipherText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decrypting bdinfo")
		os.Exit(1)
	}

	if outputFile != "" {
		finalOutput := make([]byte, BDINFO_LEN)
		copy(finalOutput, bdinfoDecrypted)
		err = os.WriteFile(outputFile, finalOutput, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error writing output file")
			os.Exit(1)
		}
	} else {
		bdinfoValues, err := parseBdinfo(bdinfoDecrypted, BDINFO_DEC_LEN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing bdinfo")
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

	// 💡 【核心修复】动态清洗 C 语言转义残留：把 \n, \, 空格 全部安全还原
	cleanedKey := RSA_KEY
	cleanedKey = strings.ReplaceAll(cleanedKey, `\n`, "\n")
	cleanedKey = strings.ReplaceAll(cleanedKey, `\`, "")
	cleanedKey = strings.ReplaceAll(cleanedKey, ` `, "")
	
	// 重新拼回标准的 PEM 格式换行结构
	cleanedKey = strings.ReplaceAll(cleanedKey, "-----BEGINRSAPUBLICKEY-----", "-----BEGIN RSA PUBLIC KEY-----\n")
	cleanedKey = strings.ReplaceAll(cleanedKey, "-----ENDRSAPUBLICKEY-----", "\n-----END RSA PUBLIC KEY-----")

	block, _ := pem.Decode([]byte(cleanedKey))
	if block == nil {
		return fmt.Errorf("Internal PEM Decode failed")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.MD5, md5Digest, rsaSignature)
	if err != nil {
		return err
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

func decryptDesCbc(cipherText []byte) ([]byte, error) {
	keyBytes := opensslStringToKey(DES_KEY)

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	ivBytes := make([]byte, des.BlockSize) 
	mode := newCBCDecrypter(block, ivBytes)

	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	return decrypted, nil
}

func parseBdinfo(data []byte, maxLen int) ([]string, error) {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	text := string(data)
	if !strings.Contains(text, BDINFO_END_MAGIC) {
		return nil, fmt.Errorf("EOF Marker not found")
	}

	rawLines := strings.Split(text, "\n")
	var finalLines []string

	for _, line := range rawLines {
		if len(finalLines) >= BDINFO_VAL_NUM_VALS {
			break
		}
		if strings.HasPrefix(line, BDINFO_END_MAGIC) {
			break
		}
		finalLines = append(finalLines, line)
	}

	kvPairs := make([]string, 0, len(finalLines)*2)

	for _, line := range finalLines {
		sepIndex := strings.Index(line, "=")
		if sepIndex == -1 {
			return nil, fmt.Errorf("Invalid line without separator")
		}

		key := line[:sepIndex]
		value := line[sepIndex+1:]
		value = strings.TrimRight(value, "\r\x00")

		kvPairs = append(kvPairs, key, value)
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

// ====== CBC 解密器结构体与接口实现 ======
type cbcDecrypter struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
}

func newCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		tmp:       make([]byte, b.BlockSize()),
	}
}

func (x *cbcDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *cbcDecrypter) Neighbors() (next, prev cipher.BlockMode) {
	return nil, nil
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
