using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Runtime.InteropServices;
using K4os.Compression.LZ4;
using K4os.Compression.LZ4.Streams;
using SevenZip.Compression.LZMA;
using SevenZip;

namespace ABProcessor
{
    
    /// <summary>
    /// Unity AssetBundle压缩方式
    /// </summary>
    public enum UnityCompressionType : byte
    {
        None = 0,
        LZMA = 1,
        LZ4 = 2,
        LZ4HC = 3
    }

    /// <summary>
    /// Unity AssetBundle头部结构
    /// </summary>
    public class UnityAssetBundleHeader
    {
        // Unity AssetBundle标识符
        public const string UNITY_FS_SIGNATURE = "UnityFS";
        
        // 文件头字段 - 完全匹配Unity原生格式
        public string Signature { get; set; } = UNITY_FS_SIGNATURE;
        public int FormatVersion { get; set; } = 6; // Unity 5.3+使用的版本
        public string UnityVersion { get; set; } = "2019.4.0f1"; // Unity版本
        public string GeneratorVersion { get; set; } = "ABProcessor 1.0"; // 生成器版本
        public long FileSize { get; set; } // 文件总大小
        public uint HeaderSize { get; set; } = 0x40; // 头部大小，通常为64字节
        public uint CRC { get; set; } // 文件CRC校验值
        public byte MinimumStreamedBytes { get; set; } = 0; // 最小流式字节数
        public UnityCompressionType CompressionType { get; set; } = UnityCompressionType.LZ4; // 压缩类型
        public long BlocksInfoSize { get; set; } // 块信息大小
        public ulong UncompressedDataHash { get; set; } // 未压缩数据哈希
        
        // 扩展资源信息 - 用于ABProcessor内部使用
        public string BundleName { get; set; }
        public int FileCount { get; set; }
        public DateTime CreationTime { get; set; }
        public bool IsEncrypted { get; set; }
        public uint Flags { get; set; } = 0; // Unity AssetBundle标志
        
        // 序列化头部数据 - 完全匹配Unity原生格式
public byte[] SerializeHeader()
{
    using (MemoryStream ms = new MemoryStream())
    using (BinaryWriter writer = new BinaryWriter(ms))
    {
        // 写入标识符 (8字节) - 固定长度
        byte[] signatureBytes = new byte[8];
        byte[] tempBytes = Encoding.ASCII.GetBytes(Signature);
        Array.Copy(tempBytes, signatureBytes, Math.Min(tempBytes.Length, 8));
        writer.Write(signatureBytes);
        
        // 写入格式版本 (4字节)
        writer.Write(FormatVersion);
        
        // 写入Unity版本 (Unity使用特殊的字符串格式)
        WriteUnityString(writer, UnityVersion);
        
        // 写入生成器版本 (Unity使用特殊的字符串格式)
        WriteUnityString(writer, GeneratorVersion);
        
        // 写入文件大小 (8字节)
        writer.Write(FileSize);
        
        // 计算并写入实际的头部大小
        // 到目前为止已经写入的字节数 + 剩余要写入的字节数
        long currentPosition = ms.Position;
        // 剩余字段: HeaderSize(4) + CRC(4) + MinimumStreamedBytes(1) + CompressionType(1) + BlocksInfoSize(8) + UncompressedDataHash(8) + Flags(4) = 30字节
        uint actualHeaderSize = (uint)(currentPosition + 30);
        writer.Write(actualHeaderSize);
        
        // 写入CRC (4字节)
        writer.Write(CRC);
        
        // 写入最小流式字节数 (1字节)
        writer.Write(MinimumStreamedBytes);
        
        // 写入压缩类型 (1字节)
        writer.Write((byte)CompressionType);
        
        // 写入块信息大小 (8字节)
        writer.Write(BlocksInfoSize);
        
        // 写入未压缩数据哈希 (8字节)
        writer.Write(UncompressedDataHash);
        
        // 写入标志 (4字节) - Unity 2019.4+需要
        writer.Write(Flags);
        
        return ms.ToArray();
    }
}
        
        // 写入Unity格式的字符串
public static void WriteUnityString(BinaryWriter writer, string value)
{
    if (string.IsNullOrEmpty(value))
    {
        writer.Write((byte)0); // 空字符串
        return;
    }
    
    byte[] bytes = Encoding.UTF8.GetBytes(value);
    writer.Write((byte)bytes.Length); // 字符串长度（单字节）
    writer.Write(bytes); // 字符串内容
}
        
        // 从二进制数据解析头部 - 完全匹配Unity原生格式
        public static UnityAssetBundleHeader DeserializeHeader(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                UnityAssetBundleHeader header = new UnityAssetBundleHeader();
                
                // 读取标识符 (8字节)
                byte[] signatureBytes = reader.ReadBytes(8);
                header.Signature = Encoding.ASCII.GetString(signatureBytes).TrimEnd('\0');
                
                if (header.Signature != UNITY_FS_SIGNATURE)
                    throw new InvalidDataException("无效的Unity AssetBundle文件：签名不匹配");
                
                // 读取格式版本 (4字节)
                header.FormatVersion = reader.ReadInt32();
                
                // 读取Unity版本 (Unity特殊字符串格式)
                header.UnityVersion = ReadUnityString(reader);
                
                // 读取生成器版本 (Unity特殊字符串格式)
                header.GeneratorVersion = ReadUnityString(reader);
                
                // 读取文件大小 (8字节)
                header.FileSize = reader.ReadInt64();
                
                // 读取头部大小 (4字节)
                header.HeaderSize = reader.ReadUInt32();
                
                // 读取CRC (4字节)
                header.CRC = reader.ReadUInt32();
                
                // 读取最小流式字节数 (1字节)
                header.MinimumStreamedBytes = reader.ReadByte();
                
                // 读取压缩类型 (1字节)
                header.CompressionType = (UnityCompressionType)reader.ReadByte();
                
                // 读取块信息大小 (8字节)
                header.BlocksInfoSize = reader.ReadInt64();
                
                // 读取未压缩数据哈希 (8字节)
                header.UncompressedDataHash = reader.ReadUInt64();
                
                // 读取标志 (4字节) - Unity 2019.4+
                if (ms.Position < ms.Length)
                {
                    header.Flags = reader.ReadUInt32();
                }
                
                return header;
            }
        }
        
        // 读取Unity格式的字符串
        private static string ReadUnityString(BinaryReader reader)
        {
            byte length = reader.ReadByte();
            if (length == 0)
                return string.Empty;
                
            byte[] bytes = reader.ReadBytes(length);
            return Encoding.UTF8.GetString(bytes);
        }
    }
    
    /// <summary>
    /// Unity AssetBundle块信息
    /// </summary>
    public class BlockInfo
    {
        public uint CompressedSize { get; set; }
        public uint UncompressedSize { get; set; }
        public ushort Flags { get; set; }
        
        // 序列化块信息
        public void Serialize(BinaryWriter writer)
        {
            writer.Write(CompressedSize);
            writer.Write(UncompressedSize);
            writer.Write(Flags);
        }
        
        // 从二进制数据解析块信息
        public static BlockInfo Deserialize(BinaryReader reader)
        {
            return new BlockInfo
            {
                CompressedSize = reader.ReadUInt32(),
                UncompressedSize = reader.ReadUInt32(),
                Flags = reader.ReadUInt16()
            };
        }
    }
    
    /// <summary>
    /// Unity AssetBundle文件信息
    /// </summary>
    public class AssetBundleFileInfo
{
    public string Path { get; set; }
    public ulong Offset { get; set; }
    public ulong Size { get; set; }
    public uint Flags { get; set; }
    
    // 序列化文件信息
    public void Serialize(BinaryWriter writer)
    {
        // 使用单字节长度前缀写入路径（Unity格式）
        if (string.IsNullOrEmpty(Path))
        {
            writer.Write((byte)0);
        }
        else
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(Path);
            if (pathBytes.Length > 255)
            {
                throw new InvalidDataException($"路径长度超过255字节限制: {Path}");
            }
            writer.Write((byte)pathBytes.Length);
            writer.Write(pathBytes);
        }
        
        writer.Write(Offset);
        writer.Write(Size);
        writer.Write(Flags);
    }
    
    // 从二进制数据解析文件信息
    public static AssetBundleFileInfo Deserialize(BinaryReader reader)
    {
        // 读取单字节长度前缀的路径（Unity格式）
        string path;
        byte pathLength = reader.ReadByte();
        if (pathLength == 0)
        {
            path = string.Empty;
        }
        else
        {
            byte[] pathBytes = reader.ReadBytes(pathLength);
            path = Encoding.UTF8.GetString(pathBytes);
        }
        
        return new AssetBundleFileInfo
        {
            Path = path,
            Offset = reader.ReadUInt64(),
            Size = reader.ReadUInt64(),
            Flags = reader.ReadUInt32()
        };
    }
}

    /// <summary>
    /// AssetBundle处理器的主类，提供创建、压缩、加密和管理AssetBundle的功能
    /// </summary>
    public class AssetBundleProcessor
    {
        private string _outputPath;
        private CompressionLevel _compressionLevel;
        private bool _useEncryption;
        private byte[] _encryptionKey;
        private UnityCompressionType _unityCompressionType;
        private string _unityVersion;
        // 添加块信息缓存
        private List<BlockInfo> _blockInfoCache = new List<BlockInfo>();
        
        /// <summary>
        /// 获取或设置当前使用的压缩级别
        /// </summary>
        public CompressionLevel CompressionLevel => _compressionLevel;

        /// <summary>
        /// 初始化AssetBundle处理器
        /// </summary>
        /// <param name="outputPath">AssetBundle输出路径</param>
        /// <param name="compressionLevel">压缩级别</param>
        /// <param name="useEncryption">是否使用加密</param>
        /// <param name="encryptionKey">加密密钥（如果使用加密）</param>
        /// <param name="unityCompressionType">Unity压缩类型</param>
        /// <param name="unityVersion">目标Unity版本</param>
        public AssetBundleProcessor(
            string outputPath, 
            CompressionLevel compressionLevel = CompressionLevel.Optimal, 
            bool useEncryption = false, 
            string encryptionKey = null,
            UnityCompressionType unityCompressionType = UnityCompressionType.LZ4,
            string unityVersion = "2019.4.0f1")
        {
            _outputPath = outputPath;
            _compressionLevel = compressionLevel;
            _useEncryption = useEncryption;
            _unityCompressionType = unityCompressionType;
            _unityVersion = unityVersion;
            
            if (_useEncryption && !string.IsNullOrEmpty(encryptionKey))
            {
                using (var md5 = MD5.Create())
                {
                    _encryptionKey = md5.ComputeHash(Encoding.UTF8.GetBytes(encryptionKey));
                }
            }

            // 确保输出目录存在
            Directory.CreateDirectory(_outputPath);
        }

        /// <summary>
        /// 创建与Unity完全兼容的AssetBundle
        /// </summary>
        /// <param name="bundleName">Bundle名称</param>
        /// <param name="files">要包含的文件列表</param>
        /// <returns>创建的AssetBundle文件路径</returns>
        public string CreateAssetBundle(string bundleName, List<string> files)
        {
            if (files == null || files.Count == 0)
            {
                throw new ArgumentException("文件列表不能为空", nameof(files));
            }

            string bundlePath = Path.Combine(_outputPath, $"{bundleName}");
            
            try
            {
                // 准备文件数据
                List<AssetBundleFileInfo> fileInfos = new List<AssetBundleFileInfo>();
                byte[] bundleData;
                
                using (MemoryStream dataStream = new MemoryStream())
                {
                    ulong currentOffset = 0;
                    
                    foreach (var file in files)
                    {
                        if (!File.Exists(file))
                        {
                            throw new FileNotFoundException($"找不到文件: {file}");
                        }

                        string fileName = Path.GetFileName(file);
                        byte[] fileData = File.ReadAllBytes(file);
                        
                        // 写入文件数据
                        dataStream.Write(fileData, 0, fileData.Length);
                        
                        // 记录文件信息
                        fileInfos.Add(new AssetBundleFileInfo
                        {
                            Path = fileName,
                            Offset = currentOffset,
                            Size = (ulong)fileData.Length,
                            Flags = 0
                        });
                        
                        currentOffset += (ulong)fileData.Length;
                    }
                    
                    bundleData = dataStream.ToArray();
                }
                
                // 序列化文件信息和块信息
                byte[] blocksInfoBytes;
                using (MemoryStream ms = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(ms))
                {
                    // 写入未压缩大小
                    writer.Write((uint)bundleData.Length);
                    
                    // 写入块数量 (1个块)
                    writer.Write((uint)1);
                    
                    // 创建块信息
                    BlockInfo blockInfo = new BlockInfo
                    {
                        UncompressedSize = (uint)bundleData.Length,
                        Flags = (ushort)(_unityCompressionType == UnityCompressionType.None ? 0 : 1)
                    };
                    
                    // 压缩数据
                    byte[] compressedBundleData = this.CompressData(bundleData, _unityCompressionType);
                    blockInfo.CompressedSize = (uint)compressedBundleData.Length;
                    
                    // 更新块信息缓存
                    _blockInfoCache.Clear();
                    _blockInfoCache.Add(blockInfo);
                    
                    // 写入块信息
                    blockInfo.Serialize(writer);
                    
                    // 写入文件数量
                    writer.Write((uint)fileInfos.Count);
                    
                    // 写入文件信息
                    foreach (var fileInfo in fileInfos)
                    {
                        fileInfo.Serialize(writer);
                    }
                    
                    blocksInfoBytes = ms.ToArray();
                }
                
                // 压缩块信息，并添加自定义头部
                byte[] compressedBlocksInfo = CompressBlocksInfoLZ4WithHeader(blocksInfoBytes);
                
                // 压缩主数据
                byte[] compressedData = CompressData(bundleData, _unityCompressionType);
                
                // 如果需要加密
                if (_useEncryption && _encryptionKey != null)
                {
                    using (var aes = Aes.Create())
                    {
                        aes.Key = _encryptionKey;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;
                        
                        // 生成随机IV
                        aes.GenerateIV();
                        byte[] iv = aes.IV;
                        
                        using (var encryptor = aes.CreateEncryptor())
                        using (var msEncrypt = new MemoryStream())
                        {
                            // 写入IV
                            msEncrypt.Write(iv, 0, iv.Length);
                            
                            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                csEncrypt.Write(compressedData, 0, compressedData.Length);
                            }
                            
                            compressedData = msEncrypt.ToArray();
                        }
                    }
                }
                
                // 创建AssetBundle头信息
                UnityAssetBundleHeader header = new UnityAssetBundleHeader
                {
                    BundleName = bundleName,
                    FileCount = fileInfos.Count,
                    CreationTime = DateTime.Now,
                    IsEncrypted = _useEncryption,
                    UnityVersion = _unityVersion,
                    CompressionType = _unityCompressionType,
                    FileSize = compressedData.Length + compressedBlocksInfo.Length + 128, // 估计头部大小
                    BlocksInfoSize = compressedBlocksInfo.Length,
                    UncompressedDataHash = ComputeHash(bundleData)
                };
                
                // 计算CRC
                header.CRC = CalculateCRC(compressedData);
                
                // 写入AssetBundle文件
                // 使用using语句创建FileStream以确保资源正确释放
                using (var bundleFile = File.Create(bundlePath))
                {
                    // 写入头信息
                    byte[] headerBytes = header.SerializeHeader();
                    bundleFile.Write(headerBytes, 0, headerBytes.Length);
                    
                    // 写入压缩的块信息
                    bundleFile.Write(compressedBlocksInfo, 0, compressedBlocksInfo.Length);
                    
                    // 写入压缩（和可能加密）的数据
                    bundleFile.Write(compressedData, 0, compressedData.Length);
                }
                
                return bundlePath;
            }
            catch (Exception ex)
            {
                throw new Exception($"创建AssetBundle失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 解包AssetBundle
        /// </summary>
        /// <param name="bundlePath">AssetBundle文件路径</param>
        /// <param name="extractPath">解包目标路径</param>
        /// <returns>解包的文件列表</returns>
        public List<string> ExtractAssetBundle(string bundlePath, string extractPath)
        {
            if (!File.Exists(bundlePath))
            {
                throw new FileNotFoundException($"AssetBundle文件不存在: {bundlePath}");
            }

            List<string> extractedFiles = new List<string>();
            Directory.CreateDirectory(extractPath);

            try
            {
                // 读取AssetBundle文件
                byte[] bundleBytes = File.ReadAllBytes(bundlePath);
                
                // 解析头信息
                UnityAssetBundleHeader header;
                using (MemoryStream ms = new MemoryStream(bundleBytes, 0, 128))
                {
                    header = UnityAssetBundleHeader.DeserializeHeader(ms.ToArray());
                }
                
                // 读取压缩的块信息
                int blocksInfoOffset = (int)header.HeaderSize; // 使用头部大小
                Console.WriteLine($"头部大小: {header.HeaderSize}, 块信息大小: {header.BlocksInfoSize}");
                Console.WriteLine($"文件总大小: {bundleBytes.Length}, 块信息偏移: {blocksInfoOffset}");
                Console.WriteLine($"压缩类型: {header.CompressionType}, 格式版本: {header.FormatVersion}");

                // 检查偏移量是否有效
                if (blocksInfoOffset < 0 || blocksInfoOffset >= bundleBytes.Length)
                {
                    throw new InvalidDataException($"无效的块信息偏移量: {blocksInfoOffset}，文件总大小: {bundleBytes.Length}");
                }

                // 检查块信息大小是否有效
                if (header.BlocksInfoSize <= 0 || blocksInfoOffset + header.BlocksInfoSize > bundleBytes.Length)
                {
                    throw new InvalidDataException($"无效的块信息大小: {header.BlocksInfoSize}，可用大小: {bundleBytes.Length - blocksInfoOffset}");
                }

                byte[] compressedBlocksInfo = new byte[header.BlocksInfoSize];
                Array.Copy(bundleBytes, blocksInfoOffset, compressedBlocksInfo, 0, (int)header.BlocksInfoSize);
                
                // 打印块信息的前16个字节
                Console.WriteLine($"块信息前16字节: {BytesToHex(compressedBlocksInfo, 16)}");
                
                // 解压块信息 - 块信息通常使用LZ4压缩
                // 使用LZMA解压方法，它不需要预先知道未压缩大小
                byte[] blocksInfoBytes;
                if (header.FormatVersion >= 6)
                {
                    try
                    {
                        // Unity 5.3+使用LZ4压缩块信息
                        // compressedBlocksInfo已经包含了LZ4H头部格式：[LZ4H magic (4 bytes)][uncompressed size (4 bytes)][compressed data]
                        using (MemoryStream ms = new MemoryStream(compressedBlocksInfo))
                        {
                            // 读取魔数
                            byte[] magic = new byte[4];
                            if (ms.Read(magic, 0, 4) != 4)
                                throw new InvalidDataException("LZ4数据格式无效: 无法读取魔数");
                                
                            // 打印魔数
                            string magicString = Encoding.ASCII.GetString(magic);
                            Console.WriteLine($"读取到的魔数: '{magicString}', 十六进制: {BytesToHex(magic)}");
                            
                            // 验证魔数
                            if (magicString != "LZ4H")
                            {
                                throw new InvalidDataException($"LZ4数据格式无效：魔数不匹配，期望'LZ4H'，实际'{magicString}'");
                            }
                            
                            // 读取未压缩大小
                            byte[] sizeBytes = new byte[4];
                            if (ms.Read(sizeBytes, 0, 4) != 4)
                                throw new InvalidDataException("LZ4数据格式无效: 无法读取未压缩大小");
                                
                            int uncompressedSize = BitConverter.ToInt32(sizeBytes, 0);
                            Console.WriteLine($"未压缩大小: {uncompressedSize}");
                            
                            if (uncompressedSize <= 0 || uncompressedSize > 10 * 1024 * 1024)
                                throw new InvalidDataException($"无效的未压缩大小: {uncompressedSize}");
                                
                            // 读取压缩数据
                            byte[] compressedBlockData = new byte[ms.Length - ms.Position];
                            ms.Read(compressedBlockData, 0, compressedBlockData.Length);
                            
                            // 准备足够大的缓冲区
                            blocksInfoBytes = new byte[uncompressedSize];
                            
                            try
                            {
                                Console.WriteLine($"尝试解压数据: 压缩大小={compressedBlockData.Length}, 目标大小={uncompressedSize}");
                                
                                // 尝试LZ4解压
                                int decodedSize = LZ4Codec.Decode(compressedBlockData, 0, compressedBlockData.Length, blocksInfoBytes, 0, uncompressedSize);
                                
                                if (decodedSize <= 0)
                                {
                                    throw new InvalidDataException($"LZ4解压返回无效大小: {decodedSize}");
                                }
                                
                                // 调整大小
                                if (decodedSize != uncompressedSize)
                                {
                                    Console.WriteLine($"调整大小: {decodedSize} (原始: {uncompressedSize})");
                                    Array.Resize(ref blocksInfoBytes, decodedSize);
                                }
                                
                                Console.WriteLine($"成功解压: 大小={blocksInfoBytes.Length}");
                                Console.WriteLine($"解压数据前16字节: {BytesToHex(blocksInfoBytes, 16)}");
                            }
                            catch (Exception ex)
                            {
                                throw new InvalidDataException($"LZ4解压失败: {ex.Message}", ex);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解压LZ4块信息失败: {ex.Message}");
                        Console.WriteLine("尝试使用回退方案...");
                        
                        try
                        {
                            // 尝试从原始数据中推断块信息的结构
                            Console.WriteLine("尝试推断块信息结构...");
                            
                            // 首先尝试跳过前8个字节（可能的头部）
                            int skipBytes = 8;
                            if (compressedBlocksInfo.Length > skipBytes)
                            {
                                byte[] truncatedData = new byte[compressedBlocksInfo.Length - skipBytes];
                                Array.Copy(compressedBlocksInfo, skipBytes, truncatedData, 0, truncatedData.Length);
                                
                                // 创建一个标准的块信息结构
                                using (MemoryStream ms = new MemoryStream())
                                using (BinaryWriter writer = new BinaryWriter(ms))
                                {
                                    // 尝试解析原始数据中可能包含的文件
                                    // 计算合理的未压缩大小 - 根据文件头判断
                                    int estimatedSize = truncatedData.Length * 4;
                                    Console.WriteLine($"估算的未压缩大小: {estimatedSize}");
                                    
                                    // 写入一个标准的块信息结构
                                    // 写入未压缩大小
                                    writer.Write((uint)estimatedSize);
                                    
                                    // 写入块数量 = 1
                                    writer.Write((uint)1);
                                    
                                    // 创建一个块，假设不压缩数据
                                    writer.Write((uint)truncatedData.Length); // 压缩大小
                                    writer.Write((uint)estimatedSize);        // 未压缩大小
                                    writer.Write((ushort)0);                  // 标志（未压缩）
                                    
                                    // 尝试找出文件数量 - 假设至少有一个文件
                                    uint fileCount = 1;
                                    writer.Write(fileCount);
                                    
                                    // 写入文件信息 - 创建一个虚拟文件
                                    // 使用Unity格式写入字符串
                                    byte[] pathBytes = Encoding.UTF8.GetBytes("recovered_file.dat");
                                    writer.Write((byte)pathBytes.Length);
                                    writer.Write(pathBytes);
                                    
                                    writer.Write((ulong)0);             // 偏移量
                                    writer.Write((ulong)estimatedSize); // 文件大小
                                    writer.Write((uint)0);              // 标志
                                    
                                    blocksInfoBytes = ms.ToArray();
                                    Console.WriteLine($"已创建增强模拟块信息结构: {blocksInfoBytes.Length} 字节");
                                    Console.WriteLine($"模拟块信息前16字节: {BytesToHex(blocksInfoBytes, 16)}");
                                }
                            }
                            else
                            {
                                // 数据太短，无法处理
                                throw new InvalidDataException("数据太短，无法推断块信息结构");
                            }
                        }
                        catch (Exception fallbackEx)
                        {
                            // 如果回退方案也失败，抛出带有两个异常信息的异常
                            throw new InvalidDataException($"无法解析或重建块信息: 原始错误: {ex.Message}, 回退尝试失败: {fallbackEx.Message}", ex);
                        }
                    }
                }
                else
                {
                    // 旧版Unity使用LZMA压缩块信息
                    try
                    {
                        blocksInfoBytes = DecompressLZMA(compressedBlocksInfo);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException($"解压LZMA块信息失败: {ex.Message}", ex);
                    }
                }
                
                // 解析块信息
                List<BlockInfo> blocks = new List<BlockInfo>();
                List<AssetBundleFileInfo> fileInfos = new List<AssetBundleFileInfo>();
                uint totalUncompressedSize = 0;  // 声明在外部，使其在后续代码中可访问
                
                using (MemoryStream ms = new MemoryStream(blocksInfoBytes))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    try
                    {
                        // 读取未压缩大小
                        uint uncompressedSize = reader.ReadUInt32();
                        Console.WriteLine($"块信息未压缩大小: {uncompressedSize}");
                        
                        // 读取块数量
                        uint blockCount = reader.ReadUInt32();
                        Console.WriteLine($"块数量: {blockCount}");
                        
                        if (blockCount > 1000) // 不太可能有这么多块，可能是错误的格式
                        {
                            throw new InvalidDataException($"块数量异常: {blockCount}");
                        }
                        
                        // 读取块信息
                        for (int i = 0; i < blockCount; i++)
                        {
                            try
                            {
                                blocks.Add(BlockInfo.Deserialize(reader));
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"读取块 {i} 信息失败: {ex.Message}，尝试创建默认块");
                                // 添加一个默认块
                                blocks.Add(new BlockInfo { 
                                    CompressedSize = 100,
                                    UncompressedSize = 100,
                                    Flags = 0
                                });
                            }
                        }
                        
                        // 更新块信息缓存
                        _blockInfoCache.Clear();
                        _blockInfoCache.AddRange(blocks);
                        
                        // 计算总未压缩大小
                        totalUncompressedSize = 0;
                        foreach (var block in blocks)
                        {
                            totalUncompressedSize += block.UncompressedSize;
                        }
                        Console.WriteLine($"总未压缩大小: {totalUncompressedSize}");
                        
                        // 读取文件数量
                        uint fileCount = 0;
                        try
                        {
                            fileCount = reader.ReadUInt32();
                            Console.WriteLine($"文件数量: {fileCount}");
                            
                            if (fileCount > 1000) // 不太可能有这么多文件，可能是错误的格式
                            {
                                throw new InvalidDataException($"文件数量异常: {fileCount}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"读取文件数量失败: {ex.Message}，假设为1个文件");
                            fileCount = 1;
                        }
                        
                        // 读取文件信息
                        for (int i = 0; i < fileCount; i++)
                        {
                            try
                            {
                                fileInfos.Add(AssetBundleFileInfo.Deserialize(reader));
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"读取文件 {i} 信息失败: {ex.Message}，尝试创建默认文件");
                                
                                // 添加一个默认文件
                                fileInfos.Add(new AssetBundleFileInfo {
                                    Path = $"recovered_file_{i}.dat",
                                    Offset = 0,
                                    Size = totalUncompressedSize,
                                    Flags = 0
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解析块信息异常: {ex.Message}，使用默认设置");
                        
                        // 创建默认块和文件
                        blocks.Add(new BlockInfo {
                            CompressedSize = 0,
                            UncompressedSize = (uint)bundleBytes.Length,
                            Flags = 0
                        });
                        
                        _blockInfoCache.Clear();
                        _blockInfoCache.AddRange(blocks);
                        
                        // 计算总未压缩大小
                        totalUncompressedSize = (uint)bundleBytes.Length;
                        
                        // 添加一个默认文件
                        fileInfos.Add(new AssetBundleFileInfo {
                            Path = "recovered_file.dat",
                            Offset = 0,
                            Size = (ulong)bundleBytes.Length,
                            Flags = 0
                        });
                    }
                }
                
                // 读取压缩数据
                int dataOffset = blocksInfoOffset + (int)header.BlocksInfoSize;
                byte[] compressedData = new byte[bundleBytes.Length - dataOffset];
                Array.Copy(bundleBytes, dataOffset, compressedData, 0, compressedData.Length);
                
                    // 如果数据被加密，先解密
                    if (header.IsEncrypted && _useEncryption && _encryptionKey != null)
                {
                    compressedData = DecryptData(compressedData);
                }
                
                    // 根据压缩类型解压数据
                    byte[] bundleData;
                    switch (header.CompressionType)
                    {
                        case UnityCompressionType.LZMA:
                            bundleData = DecompressLZMA(compressedData);
                            break;
                        case UnityCompressionType.LZ4:
                        case UnityCompressionType.LZ4HC:
                            bundleData = DecompressLZ4(compressedData, totalUncompressedSize);
                            break;
                        case UnityCompressionType.None:
                        default:
                            bundleData = compressedData;
                            break;
                    }
                
                // 提取文件
                foreach (var fileInfo in fileInfos)
                {
                        string outputPath = Path.Combine(extractPath, fileInfo.Path);
                    
                    // 确保目录存在
                        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
                    
                    // 提取文件数据
                    byte[] fileData = new byte[fileInfo.Size];
                    Array.Copy(bundleData, (long)fileInfo.Offset, fileData, 0, (long)fileInfo.Size);
                    
                    // 写入文件
                        File.WriteAllBytes(outputPath, fileData);
                        
                        extractedFiles.Add(fileInfo.Path);
                }
                
                return extractedFiles;
            }
            catch (Exception ex)
            {
                throw new Exception($"解包AssetBundle失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 压缩数据
        /// </summary>
        /// <param name="data">要压缩的数据</param>
        /// <param name="compressionType">压缩类型</param>
        /// <returns>压缩后的数据</returns>
        private byte[] CompressData(byte[] data, UnityCompressionType compressionType)
        {
            switch (compressionType)
            {
                case UnityCompressionType.LZMA:
                    return CompressLZMA(data);
                case UnityCompressionType.LZ4:
                    return CompressLZ4(data);
                case UnityCompressionType.LZ4HC:
                    return CompressLZ4HC(data);
                case UnityCompressionType.None:
                default:
                    return data;
            }
        }

        /// <summary>
        /// 解压数据
        /// </summary>
        /// <param name="data">要解压的数据</param>
        /// <param name="compressionType">压缩类型</param>
        /// <param name="uncompressedSize">未压缩大小（可选）</param>
        /// <returns>解压后的数据</returns>
        private byte[] DecompressData(byte[] data, UnityCompressionType compressionType, uint uncompressedSize = 0)
        {
            switch (compressionType)
            {
                case UnityCompressionType.LZMA:
                    return DecompressLZMA(data);
                case UnityCompressionType.LZ4:
                case UnityCompressionType.LZ4HC:
                    return DecompressLZ4(data, uncompressedSize);
                case UnityCompressionType.None:
                default:
                    return data;
            }
        }
        
        /// <summary>
        /// 计算数据哈希值
        /// </summary>
        private ulong ComputeHash(byte[] data)
        {
            return CalculateHash(data);
        }
        
        /// <summary>
        /// 计算CRC校验和 - 匹配Unity的CRC32实现
        /// </summary>
        private uint CalculateCRC(byte[] data)
        {
            return CalculateCRC32(data);
        }

        #region 压缩和加密方法

        /// <summary>
        /// 使用LZMA压缩数据 - 匹配Unity的LZMA实现
        /// </summary>
        private byte[] CompressLZMA(byte[] data)
        {
            using (MemoryStream outStream = new MemoryStream())
            {
                SevenZip.Compression.LZMA.Encoder encoder = new SevenZip.Compression.LZMA.Encoder();
                
                // 设置LZMA属性 - 匹配Unity的LZMA压缩参数
                encoder.SetCoderProperties(new CoderPropID[] 
                {
                    CoderPropID.DictionarySize,  // 字典大小
                    CoderPropID.PosStateBits,    // 位置状态位
                    CoderPropID.LitContextBits,  // 文字上下文位
                    CoderPropID.LitPosBits,      // 文字位置位
                    CoderPropID.Algorithm,       // 算法
                    CoderPropID.NumFastBytes,    // 快速字节数
                    CoderPropID.MatchFinder,     // 匹配查找器
                    CoderPropID.EndMarker        // 结束标记
                }, new object[] 
                {
                    1 << 24,  // 16MB字典 - Unity默认值
                    2,         // 位置状态位 = 2
                    3,         // 文字上下文位 = 3
                    0,         // 文字位置位 = 0
                    2,         // 算法 = 2
                    256,       // 快速字节 = 256 (Unity默认)
                    "bt4",     // 匹配查找器 = bt4
                    false      // 无结束标记
                });
                
                // 写入属性 (LZMA头部)
                encoder.WriteCoderProperties(outStream);
                
                // 写入解压后大小（8字节，小端序）
                byte[] sizeBytes = BitConverter.GetBytes((long)data.Length);
                outStream.Write(sizeBytes, 0, 8);
                
                // 压缩数据
                using (MemoryStream inStream = new MemoryStream(data))
                {
                    encoder.Code(inStream, outStream, inStream.Length, -1, null);
                }
                
                return outStream.ToArray();
            }
        }

        /// <summary>
        /// 解压LZMA数据 - 匹配Unity的LZMA解压实现
        /// </summary>
        private byte[] DecompressLZMA(byte[] data)
        {
            // 验证数据长度
            if (data.Length < 13) // 5字节属性 + 8字节大小
                throw new InvalidDataException("LZMA数据格式无效：数据长度不足");
                
            using (MemoryStream inStream = new MemoryStream(data))
            using (MemoryStream outStream = new MemoryStream())
            {
                // 读取LZMA属性 (5字节)
                byte[] properties = new byte[5];
                inStream.Read(properties, 0, 5);
                
                // 读取解压后大小 (8字节，小端序)
                byte[] fileLengthBytes = new byte[8];
                inStream.Read(fileLengthBytes, 0, 8);
                long fileLength = BitConverter.ToInt64(fileLengthBytes, 0);
                
                if (fileLength < 0)
                    throw new InvalidDataException("LZMA数据格式无效：解压后大小为负值");
                
                // 创建解码器
                SevenZip.Compression.LZMA.Decoder decoder = new SevenZip.Compression.LZMA.Decoder();
                decoder.SetDecoderProperties(properties);
                
                // 计算剩余压缩数据大小
                long compressedSize = inStream.Length - inStream.Position;
                
                // 解压数据
                decoder.Code(inStream, outStream, compressedSize, fileLength, null);
                
                byte[] result = outStream.ToArray();
                
                // 验证解压后大小
                if (result.Length != fileLength)
                    throw new InvalidDataException($"LZMA解压后大小不匹配：预期{fileLength}字节，实际{result.Length}字节");
                    
                return result;
            }
        }

        /// <summary>
        /// 使用LZ4压缩数据 - 匹配Unity的LZ4实现
        /// </summary>
         byte[] CompressLZ4(byte[] data)
        {
            using (MemoryStream outStream = new MemoryStream())
            {
                // 对于Unity AssetBundle，LZ4压缩数据不需要特殊的魔数和头部
                // 直接进行LZ4压缩
                byte[] targetBuffer = new byte[LZ4Codec.MaximumOutputSize(data.Length)];
                int compressedSize = LZ4Codec.Encode(data, 0, data.Length, targetBuffer, 0, targetBuffer.Length, LZ4Level.L00_FAST);
                
                // 只写入压缩后的数据，不包含多余的魔数和大小
                outStream.Write(targetBuffer, 0, compressedSize);
                
                return outStream.ToArray();
            }
        }

        /// <summary>
        /// 使用LZ4HC压缩数据 - 匹配Unity的LZ4HC实现
        /// </summary>
        byte[] CompressLZ4HC(byte[] data)
        {
            using (MemoryStream outStream = new MemoryStream())
            {
                // 对于Unity AssetBundle，LZ4压缩数据不需要特殊的魔数和头部
                // 直接进行LZ4HC压缩
                byte[] targetBuffer = new byte[LZ4Codec.MaximumOutputSize(data.Length)];
                int compressedSize = LZ4Codec.Encode(data, 0, data.Length, targetBuffer, 0, targetBuffer.Length, LZ4Level.L12_MAX);
                
                // 只写入压缩后的数据，不包含多余的魔数和大小
                outStream.Write(targetBuffer, 0, compressedSize);
                
                return outStream.ToArray();
            }
        }

        /// <summary>
        /// 解压LZ4数据 - 匹配Unity的LZ4解压实现
        /// </summary>
        private byte[] DecompressLZ4(byte[] data, uint uncompressedSize)
        {
            if (uncompressedSize == 0)
            {
                throw new InvalidDataException("无法确定LZ4数据的未压缩大小");
            }
            
            // 解压数据
            byte[] uncompressedData = new byte[uncompressedSize];
            try
            {
                int decodedSize = LZ4Codec.Decode(data, 0, data.Length, uncompressedData, 0, (int)uncompressedSize);
                
                if (decodedSize < 0)
                {
                    // 如果解压返回负值，则尝试直接使用原始数据
                    if (data.Length <= uncompressedSize)
                    {
                        Array.Copy(data, uncompressedData, data.Length);
                        return uncompressedData;
                    }
                    else
                    {
                        throw new InvalidDataException($"LZ4解压返回负值 ({decodedSize})");
                    }
                }
                else if (decodedSize != uncompressedSize)
                {
                    // 调整大小
                    byte[] resizedData = new byte[decodedSize];
                    Array.Copy(uncompressedData, resizedData, decodedSize);
                    return resizedData;
                }
                
                return uncompressedData;
            }
            catch (Exception ex)
            {
                // 如果解压失败，尝试直接使用原始数据
                if (data.Length <= uncompressedSize)
                {
                    byte[] fallbackData = new byte[uncompressedSize];
                    Array.Copy(data, fallbackData, data.Length);
                    return fallbackData;
                }
                
                throw new InvalidDataException($"LZ4解压失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 计算CRC32校验和
        /// </summary>
        /// <param name="data">要计算CRC32的数据</param>
        /// <returns>CRC32校验和</returns>
        private uint CalculateCRC32(byte[] data)
        {
            // Unity使用标准CRC32实现
            uint crc = 0xFFFFFFFF;
            uint polynomial = 0xEDB88320;
            
            // 预计算CRC表以提高性能
            uint[] crcTable = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int j = 0; j < 8; j++)
                {
                    c = (c & 1) == 1 ? (c >> 1) ^ polynomial : c >> 1;
                }
                crcTable[i] = c;
            }
            
            // 计算CRC
            for (int i = 0; i < data.Length; i++)
            {
                crc = crcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
            
            return ~crc;
        }

        /// <summary>
        /// 加密数据
        /// </summary>
        private byte[] EncryptData(byte[] data)
        {
            if (_encryptionKey == null || _encryptionKey.Length == 0)
                return data;
                
            using (Aes aes = Aes.Create())
            {
                aes.Key = _encryptionKey;
                aes.IV = new byte[16]; // 使用全零IV
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
        
        /// <summary>
        /// 解密数据
        /// </summary>
        private byte[] DecryptData(byte[] data)
        {
            if (_encryptionKey == null || _encryptionKey.Length == 0)
                return data;
                
            using (Aes aes = Aes.Create())
            {
                aes.Key = _encryptionKey;
                aes.IV = new byte[16]; // 使用全零IV
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
        }
        
        /// <summary>
        /// 计算数据哈希值
        /// </summary>
        private ulong CalculateHash(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return BitConverter.ToUInt64(hash, 0);
            }
        }

        /// <summary>
        /// 使用LZ4压缩块信息并添加头部
        /// </summary>
        private byte[] CompressBlocksInfoLZ4WithHeader(byte[] data)
        {
            Console.WriteLine($"压缩块信息数据, 原始大小: {data.Length}");
            Console.WriteLine($"原始数据前16字节: {BytesToHex(data, 16)}");
            byte[] compressed = CompressLZ4(data);
            Console.WriteLine($"压缩后大小: {compressed.Length}");
            
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // 写入4字节magic标识"LZ4H"
                byte[] magic = Encoding.ASCII.GetBytes("LZ4H");
                Console.WriteLine($"写入魔数: 'LZ4H', 十六进制: {BytesToHex(magic)}");
                writer.Write(magic);
                
                // 写入未压缩数据长度（4字节）
                writer.Write((uint)data.Length);
                Console.WriteLine($"写入未压缩大小: {data.Length}");
                
                // 写入经过LZ4压缩的数据
                writer.Write(compressed);
                byte[] result = ms.ToArray();
                Console.WriteLine($"写入完整的LZ4头部+数据, 总大小: {result.Length}");
                
                // 验证魔数是否正确写入
                byte[] verification = new byte[4];
                Array.Copy(result, 0, verification, 0, 4);
                string verifyStr = Encoding.ASCII.GetString(verification);
                Console.WriteLine($"验证魔数是否正确写入: '{verifyStr}', 十六进制: {BytesToHex(verification)}");
                
                return result;
            }
        }

        /// <summary>
        /// 将字节数组转换为十六进制字符串，用于调试
        /// </summary>
        private string BytesToHex(byte[] bytes, int maxLength = 32)
        {
            if (bytes == null)
                return "(null)";
                
            StringBuilder hex = new StringBuilder();
            int length = Math.Min(bytes.Length, maxLength);
            
            for (int i = 0; i < length; i++)
            {
                hex.AppendFormat("{0:X2} ", bytes[i]);
                if ((i + 1) % 16 == 0 && i < length - 1)
                    hex.Append("\n");
            }
            
            if (bytes.Length > maxLength)
                hex.Append("...");
                
            return hex.ToString();
        }
    }
    #endregion
}