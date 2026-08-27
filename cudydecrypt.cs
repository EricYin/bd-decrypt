using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;

class BdInfoParser
{
    // ====== 常量定义 (已修正原C代码中的语法错误) ======
    private const string DES_KEY = "88T3j05dtFu8=";
    
    private const string RSA_KEY = 
        "-----BEGIN RSA PUBLIC KEY-----\n" +
        "MIGJAoGBAK7cBjOnooyuBwJqTfXqcHnIPvxDPbm6IsEwtDlwKDukESn5X+v8Bre\n" +
        "xK3zylUPu1kAIFY53x+BQjnBgatYIXsffgjmm9uHqIrJlc9v8Vh4RXgCITcc4ZvB\n" +
        "NBmreHQqVOFVbF5Z5XHVgTE/8dfXRqmzuuKub9MksTpfBb8bqEhbAgMBAAE=\n" +
        "-----END RSA PUBLIC KEY-----";

    private const int BDINFO_LEN = 0xde96;          // 57002 字节
    private const int BDINFO_DATA_LEN = 0xdd80;     // 56704 字节
    private const int BDINFO_DEC_LEN = 0xdd7c;      // 56700 字节
    private const int BDINFO_RSA_OFFSET = 0xdd80;   // RSA签名偏移
    private const int BDINFO_RSA_LEN = 0x80;        // 128 字节 (RSA-1024)
    private const string BDINFO_END_MAGIC = "BDINFO_END";
    private const char BDINFO_KEY_VALUE_SEPARATOR = '=';

    // 用于存储解析后的键值对
    private static Dictionary<string, string> bdinfoValues = new Dictionary<string, string>();

    static int Main(string[] args)
    {
        // 命令行参数变量
        string inputFile = null;
        string outputFile = null;
        string targetKey = null;
        bool skipRsa = false;

        // ====== 1. 解析命令行参数 (替代 C 的 getopt) ======
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h":
                    PrintHelp();
                    return 0;
                case "-i" when i + 1 < args.Length:
                    inputFile = args[++i];
                    break;
                case "-o" when i + 1 < args.Length:
                    outputFile = args[++i];
                    break;
                case "-k" when i + 1 < args.Length:
                    targetKey = args[++i];
                    break;
                case "-r":
                    skipRsa = true;
                    break;
                default:
                    Console.Error.WriteLine($"未知参数: {args[i]}");
                    PrintHelp();
                    return 1;
            }
        }

        // 参数合法性校验
        if (string.IsNullOrEmpty(inputFile))
        {
            Console.Error.WriteLine("错误: 必须指定输入文件 (-i)。");
            return 1;
        }
        if (!string.IsNullOrEmpty(outputFile) && !string.IsNullOrEmpty(targetKey))
        {
            Console.Error.WriteLine("错误: 不能同时指定解密导出 (-o) 和 查询Key (-k)。");
            return 1;
        }

        try
        {
            // ====== 2. 读取输入文件 ======
            if (!File.Exists(inputFile))
            {
                Console.Error.WriteLine($"错误: 找不到输入文件 '{inputFile}'");
                return 1;
            }

            byte[] bdinfoEncrypted = File.ReadAllBytes(inputFile);
            if (bdinfoEncrypted.Length != BDINFO_LEN)
            {
                Console.Error.WriteLine($"错误: 读取的字节数 ({bdinfoEncrypted.Length}) 与预期大小 ({BDINFO_LEN}) 不符。");
                return 1;
            }

            // ====== 3. 验证 RSA 数字签名 (MD5) ======
            if (!skipRsa)
            {
                if (!ValidateBdinfoMd5(bdinfoEncrypted))
                {
                    Console.Error.WriteLine("错误: RSA 数字签名校验失败（文件已被篡改）！");
                    return 1;
                }
            }

            // ====== 4. DES 解密 ======
            // C 代码中写的是 bdinfo_encrypted + 4，这里同样跳过前 4 个字节
            byte[] cipherText = new byte[BDINFO_DEC_LEN];
            Array.Copy(bdinfoEncrypted, 4, cipherText, 0, BDINFO_DEC_LEN);
            
            byte[] bdinfoDecrypted = DecryptDesCbc(cipherText);

            // ====== 5. 输出处理 ======
            if (!string.IsNullOrEmpty(outputFile))
            {
                // 如果指定了 -o，直接将解密后的完整 57002 字节（或实际明文数据）写入文件
                // 保持与 C 语言写入原大小 BDINFO_LEN 的逻辑一致
                byte[] finalOutput = new byte[BDINFO_LEN];
                Array.Copy(bdinfoDecrypted, 0, finalOutput, 0, Math.Min(bdinfoDecrypted.Length, finalOutput.Length));
                File.WriteAllBytes(outputFile, finalOutput);
                Console.WriteLine($"成功将解密数据导出至: {outputFile}");
            }
            else
            {
                // 解析并打印
                string textContent = Encoding.UTF8.GetString(bdinfoDecrypted);
                if (!ParseBdinfo(textContent))
                {
                    Console.Error.WriteLine("错误: 解析 bdinfo 文本内容失败。");
                    return 1;
                }

                PrintBdinfo(targetKey);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"程序运行异常: {ex.Message}");
            return 1;
        }

        return 0;
    }

    /// <summary>
    /// 验证 RSA 数字签名与数据 MD5 是否一致
    /// </summary>
    private static bool ValidateBdinfoMd5(byte[] input)
    {
        try
        {
            // 提取文件尾部的 128 字节 RSA 签名
            byte[] rsaSignature = new byte[BDINFO_RSA_LEN];
            Array.Copy(input, BDINFO_RSA_OFFSET, rsaSignature, 0, BDINFO_RSA_LEN);

            // C# 导入 PEM 公钥
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(RSA_KEY.ToCharArray());

                // 原 C 代码使用的是带有 PKCS#1 v1.5 填充的 RSA_public_decrypt（相当于解密/公钥恢复签名）
                // 在 C# 中，我们直接使用原生的 VerifyData 校验哈希更安全可靠
                // 校验范围：文件前 BDINFO_DATA_LEN (56704) 字节
                byte[] dataToVerify = new byte[BDINFO_DATA_LEN];
                Array.Copy(input, 0, dataToVerify, 0, BDINFO_DATA_LEN);

                // 使用 MD5 算法和 PKCS1 填充模式验证签名
                return rsa.VerifyData(dataToVerify, rsaSignature, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"RSA 验证过程中出错: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// DES-CBC 解密
    /// </summary>
    private static byte[] DecryptDesCbc(byte[] cipherText)
    {
        // 将 C 语言的字符串 Key 转换为 8 字节的 DES 密钥
        // 原 C 语言使用 DES_string_to_key，它会对任意长字符串生成 8 字节密钥。
        // 这里默认提取前 8 个字节（88T3j05d），这也是最标准的平替转换
        byte[] keyBytes = Encoding.UTF8.GetBytes(DES_KEY.Substring(0, 8));
        
        // 原 C 代码中 ivec 初始化为全 0
        byte[] ivBytes = new byte[8]; 

        using (DES des = DES.Create())
        {
            des.Key = keyBytes;
            des.IV = ivBytes;
            des.Mode = CipherMode.CBC;
            // 原 C 语言底层没有自适应 Padding 阻断，这里使用 None 保持解密后的原始流大小一致
            des.Padding = PaddingMode.None; 

            using (ICryptoTransform decryptor = des.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            }
        }
    }

    /// <summary>
    /// 解析解密后的文本行
    /// </summary>
    private static bool ParseBdinfo(string text)
    {
        // 查找结束标记 BDINFO_END
        int eofIndex = text.IndexOf(BDINFO_END_MAGIC);
        if (eofIndex == -1)
        {
            Console.Error.WriteLine("错误: 未找到 EOF 结束标记 (BDINFO_END)");
            return false;
        }

        // 按行切割文本
        string[] lines = text.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        bdinfoValues.Clear();

        foreach (var line in lines)
        {
            // 如果遇到结束标记，立刻停止解析后续内容
            if (line.Contains(BDINFO_END_MAGIC))
                break;

            int sepIndex = line.IndexOf(BDINFO_KEY_VALUE_SEPARATOR);
            if (sepIndex == -1)
            {
                Console.Error.WriteLine($"警告: 跳过没有分隔符的无效行 -> {line}");
                continue;
            }

            string key = line.Substring(0, sepIndex).Trim();
            string value = line.Substring(sepIndex + 1).Trim();

            // 存入字典（C# 自动实现了唯一 Key 覆盖/管理）
            bdinfoValues[key] = value;
        }

        return true;
    }

    /// <summary>
    /// 打印解析结果
    /// </summary>
    private static void PrintBdinfo(string targetKey)
    {
        if (!string.IsNullOrEmpty(targetKey))
        {
            if (bdinfoValues.TryGetValue(targetKey, out string val))
            {
                Console.WriteLine(val);
            }
            else
            {
                Console.Error.WriteLine($"错误: 在 bdinfo 中未找到键 '{targetKey}'");
            }
        }
        else
        {
            foreach (var kvp in bdinfoValues)
            {
                Console.WriteLine($"{kvp.Key} = {kvp.Value}");
            }
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("用法: Program.exe -i <输入文件> [-o <输出文件>] [-k <配置项Key>] [-r]");
        Console.WriteLine("\t-i <file>\t输入的加密 bdinfo 文件路径");
        Console.WriteLine("\t-o <file>\t将解密后的原始明文导出到指定文件");
        Console.WriteLine("\t-k <key>\t仅获取并打印指定键(Key)的值");
        Console.WriteLine("\t-r       \t跳过 RSA 签名完整性校验");
    }
}
