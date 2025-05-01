using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ABProcessor;

namespace ABProcessor.Native.Samples
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("ABProcessor Native 示例程序");
            Console.WriteLine("============================");
            
            // 设置输出和测试目录
            string outputDir = Path.Combine(Directory.GetCurrentDirectory(), "output");
            string extractDir = Path.Combine(Directory.GetCurrentDirectory(), "extract");
            string testFilesDir = Path.Combine(Directory.GetCurrentDirectory(), "testfiles");
            
            // 确保目录存在
            Directory.CreateDirectory(outputDir);
            Directory.CreateDirectory(extractDir);
            Directory.CreateDirectory(testFilesDir);
            
            // 创建测试文件
            CreateTestFiles(testFilesDir);
            
            try
            {
                // 创建ABProcessor实例
                using (var processor = new ABProcessorNative(
                    outputDir,
                    System.IO.Compression.CompressionLevel.Optimal,
                    false, // 不使用加密
                    null,  // 无加密密钥
                    UnityCompressionType.LZ4, // 使用LZ4压缩
                    "2019.4.0f1")) // Unity版本
                {
                    // 获取测试文件列表
                    List<string> files = Directory.GetFiles(testFilesDir).ToList();
                    Console.WriteLine($"找到 {files.Count} 个测试文件：");
                    foreach (var file in files)
                    {
                        Console.WriteLine($"  - {Path.GetFileName(file)}");
                    }
                    
                    // 创建AssetBundle
                    Console.WriteLine("\n创建AssetBundle...");
                    string bundlePath = processor.CreateAssetBundle("testbundle", files);
                    Console.WriteLine($"AssetBundle创建成功：{bundlePath}");
                    Console.WriteLine($"文件大小：{new FileInfo(bundlePath).Length} 字节");
                    
                    // 解包AssetBundle
                    Console.WriteLine("\n解包AssetBundle...");
                    List<string> extractedFiles = processor.ExtractAssetBundle(bundlePath, extractDir);
                    Console.WriteLine($"解包完成，共 {extractedFiles.Count} 个文件：");
                    foreach (var file in extractedFiles)
                    {
                        Console.WriteLine($"  - {file}");
                    }
                    
                    // 验证文件完整性
                    Console.WriteLine("\n验证文件完整性...");
                    bool allValid = true;
                    foreach (var originalFile in files)
                    {
                        string fileName = Path.GetFileName(originalFile);
                        string extractedFile = Path.Combine(extractDir, fileName);
                        
                        if (!File.Exists(extractedFile))
                        {
                            Console.WriteLine($"错误：文件 {fileName} 未被解包");
                            allValid = false;
                            continue;
                        }
                        
                        byte[] originalData = File.ReadAllBytes(originalFile);
                        byte[] extractedData = File.ReadAllBytes(extractedFile);
                        
                        if (originalData.Length != extractedData.Length)
                        {
                            Console.WriteLine($"错误：文件 {fileName} 大小不匹配");
                            allValid = false;
                            continue;
                        }
                        
                        bool dataMatch = true;
                        for (int i = 0; i < originalData.Length; i++)
                        {
                            if (originalData[i] != extractedData[i])
                            {
                                dataMatch = false;
                                break;
                            }
                        }
                        
                        if (!dataMatch)
                        {
                            Console.WriteLine($"错误：文件 {fileName} 内容不匹配");
                            allValid = false;
                        }
                        else
                        {
                            Console.WriteLine($"  - {fileName} 验证通过");
                        }
                    }
                    
                    if (allValid)
                    {
                        Console.WriteLine("所有文件验证通过！");
                    }
                    else
                    {
                        Console.WriteLine("文件验证失败！");
                    }
                }
                
                // 使用加密的示例
                Console.WriteLine("\n使用加密创建AssetBundle...");
                using (ABProcessorNative processor = new ABProcessorNative(
                    outputDir,
                    System.IO.Compression.CompressionLevel.Optimal,
                    true, // 使用加密
                    "MySecretKey", // 加密密钥
                    UnityCompressionType.LZMA, // 使用LZMA压缩
                    "2019.4.0f1")) // Unity版本
                {
                    // 获取测试文件列表
                    List<string> files = Directory.GetFiles(testFilesDir).ToList();
                    
                    // 创建加密的AssetBundle
                    string bundlePath = processor.CreateAssetBundle("encrypted_testbundle", files);
                    Console.WriteLine($"加密的AssetBundle创建成功：{bundlePath}");
                    Console.WriteLine($"文件大小：{new FileInfo(bundlePath).Length} 字节");
                    
                    // 解包加密的AssetBundle
                    Console.WriteLine("\n解包加密的AssetBundle...");
                    List<string> extractedFiles = processor.ExtractAssetBundle(bundlePath, extractDir);
                    Console.WriteLine($"解包完成，共 {extractedFiles.Count} 个文件");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"错误：{ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            
            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
        
        // 创建测试文件
        static void CreateTestFiles(string directory)
        {
            // 创建文本文件
            File.WriteAllText(Path.Combine(directory, "text1.txt"), "这是测试文本文件1的内容。");
            File.WriteAllText(Path.Combine(directory, "text2.txt"), "这是测试文本文件2的内容，包含更多的文本。\n这是第二行。");
            
            // 创建二进制文件
            byte[] binaryData = new byte[1024];
            Random random = new Random();
            random.NextBytes(binaryData);
            File.WriteAllBytes(Path.Combine(directory, "binary1.bin"), binaryData);
            
            // 创建图像文件（模拟）
            byte[] imageData = new byte[4096];
            random.NextBytes(imageData);
            // 添加简单的BMP头部（仅作示例）
            imageData[0] = (byte)'B';
            imageData[1] = (byte)'M';
            File.WriteAllBytes(Path.Combine(directory, "image1.bmp"), imageData);
        }
    }
}