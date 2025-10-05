using System;
using System.Collections.Generic;
using System.IO;
using ABProcessor;

namespace ABProcessor.Samples
{
    /// <summary>
    /// ABProcessor库使用示例
    /// </summary>
    public class ABProcessorSample
    {
        /// <summary>
        /// 示例程序入口点
        /// </summary>
        public static void Main(string[] args)
        {
            Console.WriteLine("ABProcessor示例程序 - Unity AssetBundle外部处理工具");
            Console.WriteLine("=============================================");
            
            // 如果传入了/test参数，则运行测试Issue的代码
            if (args.Length > 0 && args[0] == "/test")
            {
                TestReportedIssue();
                return;
            }
            
            // 创建临时目录用于测试
            string tempDir = Path.Combine(Path.GetTempPath(), "ABProcessorTest");
            string outputDir = Path.Combine(tempDir, "Output");
            string extractDir = Path.Combine(tempDir, "Extract");
            string testFilesDir = Path.Combine(tempDir, "TestFiles");
            
            try
            {
                // 清理并创建目录
                CleanupDirectories(tempDir, outputDir, extractDir, testFilesDir);
                
                // 创建测试文件
                List<string> testFiles = CreateTestFiles(testFilesDir);
                
                Console.WriteLine("\n1. 创建AssetBundle示例");
                Console.WriteLine("-------------------------");
                
                // 创建标准LZ4压缩的AssetBundle
                CreateLZ4AssetBundle(testFiles, outputDir);
                
                // 创建LZMA压缩的AssetBundle
                CreateLZMAAssetBundle(testFiles, outputDir);
                
                // 创建加密的AssetBundle
                CreateEncryptedAssetBundle(testFiles, outputDir);
                
                Console.WriteLine("\n2. 解包AssetBundle示例");
                Console.WriteLine("-------------------------");
                
                // 解包标准LZ4 AssetBundle
                ExtractLZ4AssetBundle(outputDir, extractDir);
                
                // 解包LZMA AssetBundle
                ExtractLZMAAssetBundle(outputDir, extractDir);
                
                // 解包加密的AssetBundle
                ExtractEncryptedAssetBundle(outputDir, extractDir);
                
                Console.WriteLine("\n示例程序执行完成！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n错误: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            
            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
        
        /// <summary>
        /// 清理并创建测试目录
        /// </summary>
        private static void CleanupDirectories(string tempDir, string outputDir, string extractDir, string testFilesDir)
        {
            // 如果目录已存在，先删除
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
            
            // 创建目录
            Directory.CreateDirectory(tempDir);
            Directory.CreateDirectory(outputDir);
            Directory.CreateDirectory(extractDir);
            Directory.CreateDirectory(testFilesDir);
            
            Console.WriteLine($"创建测试目录: {tempDir}");
        }
        
        /// <summary>
        /// 创建测试文件
        /// </summary>
        private static List<string> CreateTestFiles(string testFilesDir)
        {
            List<string> testFiles = new List<string>();
            
            // 创建文本文件
            string textFile = Path.Combine(testFilesDir, "text.txt");
            File.WriteAllText(textFile, "这是一个测试文本文件，用于演示ABProcessor的功能。\n包含多行文本内容。\n支持中文和其他Unicode字符。");
            testFiles.Add(textFile);
            
            // 创建二进制文件
            string binaryFile = Path.Combine(testFilesDir, "binary.dat");
            byte[] binaryData = new byte[1024];
            new Random().NextBytes(binaryData); // 填充随机数据
            File.WriteAllBytes(binaryFile, binaryData);
            testFiles.Add(binaryFile);
            
            // 创建JSON文件
            string jsonFile = Path.Combine(testFilesDir, "config.json");
string jsonContent = "{\n   \"name\": \"ABProcessor\",\n   \"version\": \"1.0.0\",\n   \"description\": \"Unity AssetBundle外部处理库\",\n   \"settings\": {\n     \"compressionLevel\": \"optimal\",\n     \"useEncryption\": false\n   }\n}";
            File.WriteAllText(jsonFile, jsonContent);
            testFiles.Add(jsonFile);
            
            Console.WriteLine($"创建测试文件: {testFiles.Count}个文件");
            return testFiles;
        }
        
        /// <summary>
        /// 创建LZ4压缩的AssetBundle
        /// </summary>
        private static void CreateLZ4AssetBundle(List<string> files, string outputDir)
        {
            // 创建AssetBundle处理器，使用LZ4压缩
            AssetBundleProcessor processor = new AssetBundleProcessor(
                outputDir,
                System.IO.Compression.CompressionLevel.Optimal,
                false,
                null,
                UnityCompressionType.LZ4,
                "2019.4.0f1");
            
            // 创建AssetBundle
            string bundlePath = processor.CreateAssetBundle("standard_lz4.bundle", files);
            
            Console.WriteLine($"创建LZ4压缩的AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"文件大小: {new FileInfo(bundlePath).Length} 字节");
        }
        
        /// <summary>
        /// 创建LZMA压缩的AssetBundle
        /// </summary>
        private static void CreateLZMAAssetBundle(List<string> files, string outputDir)
        {
            // 创建AssetBundle处理器，使用LZMA压缩
            AssetBundleProcessor processor = new AssetBundleProcessor(
                outputDir,
                System.IO.Compression.CompressionLevel.Optimal,
                false,
                null,
                UnityCompressionType.LZMA,
                "2019.4.0f1");
            
            // 创建AssetBundle
            string bundlePath = processor.CreateAssetBundle("lzma.bundle", files);
            
            Console.WriteLine($"创建LZMA压缩的AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"文件大小: {new FileInfo(bundlePath).Length} 字节");
        }
        
        /// <summary>
        /// 创建加密的AssetBundle
        /// </summary>
        private static void CreateEncryptedAssetBundle(List<string> files, string outputDir)
        {
            // 创建AssetBundle处理器，使用LZ4压缩并启用加密
            AssetBundleProcessor processor = new AssetBundleProcessor(
                outputDir,
                System.IO.Compression.CompressionLevel.Optimal,
                true,  // 启用加密
                "MySecretKey123",  // 加密密钥
                UnityCompressionType.LZ4,
                "2019.4.0f1");
            
            // 创建AssetBundle
            string bundlePath = processor.CreateAssetBundle("encrypted.bundle", files);
            
            Console.WriteLine($"创建加密的AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"文件大小: {new FileInfo(bundlePath).Length} 字节");
        }
        
        /// <summary>
        /// 解包LZ4压缩的AssetBundle
        /// </summary>
        private static void ExtractLZ4AssetBundle(string bundleDir, string extractDir)
        {
            string bundlePath = Path.Combine(bundleDir, "standard_lz4.bundle");
            string outputPath = Path.Combine(extractDir, "standard_lz4");
            
            // 创建AssetBundle处理器
            AssetBundleProcessor processor = new AssetBundleProcessor(outputPath);
            
            // 解包AssetBundle
            List<string> extractedFiles = processor.ExtractAssetBundle(bundlePath, outputPath);
            
            Console.WriteLine($"解包LZ4 AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"提取文件数: {extractedFiles.Count}");
        }
        
        /// <summary>
        /// 解包LZMA压缩的AssetBundle
        /// </summary>
        private static void ExtractLZMAAssetBundle(string bundleDir, string extractDir)
        {
            string bundlePath = Path.Combine(bundleDir, "lzma.bundle");
            string outputPath = Path.Combine(extractDir, "lzma");
            
            // 创建AssetBundle处理器
            AssetBundleProcessor processor = new AssetBundleProcessor(outputPath);
            
            // 解包AssetBundle
            List<string> extractedFiles = processor.ExtractAssetBundle(bundlePath, outputPath);
            
            Console.WriteLine($"解包LZMA AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"提取文件数: {extractedFiles.Count}");
        }
        
        /// <summary>
        /// 解包加密的AssetBundle
        /// </summary>
        private static void ExtractEncryptedAssetBundle(string bundleDir, string extractDir)
        {
            string bundlePath = Path.Combine(bundleDir, "encrypted.bundle");
            string outputPath = Path.Combine(extractDir, "encrypted");
            
            // 创建AssetBundle处理器，需要提供相同的加密密钥
            AssetBundleProcessor processor = new AssetBundleProcessor(
                outputPath,
                System.IO.Compression.CompressionLevel.Optimal,
                true,  // 启用加密
                "MySecretKey123"  // 加密密钥
            );
            
            // 解包AssetBundle
            List<string> extractedFiles = processor.ExtractAssetBundle(bundlePath, outputPath);
            
            Console.WriteLine($"解包加密的AssetBundle: {Path.GetFileName(bundlePath)}");
            Console.WriteLine($"提取文件数: {extractedFiles.Count}");
        }

        /// <summary>
        /// 测试报告的Issue - 解决LZ4数据格式魔数不匹配问题
        /// </summary>
        private static void TestReportedIssue()
        {
            Console.WriteLine("\n测试报告的Issue - LZ4魔数不匹配问题");
            Console.WriteLine("====================================");
            
            // 设置输出和提取路径
            string outputPath = "D:/Output";
            string extractPath = "D:/Extract";
            
            // 确保目录存在
            if (!Directory.Exists(outputPath))
                Directory.CreateDirectory(outputPath);
            if (!Directory.Exists(extractPath))
                Directory.CreateDirectory(extractPath);

            try
            {
                // 创建测试文件
                List<string> testFiles = new List<string>();
                
                string testFile1 = Path.Combine(outputPath, "test1.txt");
                File.WriteAllText(testFile1, "这是测试文件1");
                testFiles.Add(testFile1);
                
                string testFile2 = Path.Combine(outputPath, "test2.txt");
                File.WriteAllText(testFile2, "这是测试文件2的内容\n这是第二行");
                testFiles.Add(testFile2);
                
                string testFile3 = Path.Combine(outputPath, "test3.txt");
                File.WriteAllText(testFile3, new string('A', 1024)); // 创建一个较大的文件
                testFiles.Add(testFile3);
                
                Console.WriteLine($"创建了 {testFiles.Count} 个测试文件");

                // 初始化处理器
                AssetBundleProcessor processor = new AssetBundleProcessor(
                    outputPath: outputPath,
                    compressionLevel: System.IO.Compression.CompressionLevel.Optimal,
                    useEncryption: false,
                    unityCompressionType: UnityCompressionType.LZ4,
                    unityVersion: "2019.4.0f1"
                );

                // 创建AssetBundle
                string bundlePath = processor.CreateAssetBundle("test_bundle", testFiles);
                Console.WriteLine($"AssetBundle已创建: {bundlePath}");

                // 解包AssetBundle
                List<string> extractedFiles = processor.ExtractAssetBundle(
                    bundlePath,
                    extractPath
                );

                Console.WriteLine($"成功解包了 {extractedFiles.Count} 个文件:");
                foreach (var file in extractedFiles)
                {
                    Console.WriteLine($"- {file}");
                    
                    // 验证文件内容是否匹配
                    string originalPath = Path.Combine(outputPath, file);
                    string extractedPath = Path.Combine(extractPath, file);
                    
                    byte[] originalContent = File.ReadAllBytes(originalPath);
                    byte[] extractedContent = File.ReadAllBytes(extractedPath);
                    
                    bool contentMatches = originalContent.Length == extractedContent.Length;
                    if (contentMatches)
                    {
                        for (int i = 0; i < originalContent.Length; i++)
                        {
                            if (originalContent[i] != extractedContent[i])
                            {
                                contentMatches = false;
                                break;
                            }
                        }
                    }
                    
                    Console.WriteLine($"  内容验证: {(contentMatches ? "通过" : "失败")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"发生错误: {ex.Message}");
                Console.WriteLine($"详细信息: {ex}");
            }
        }
    }
}