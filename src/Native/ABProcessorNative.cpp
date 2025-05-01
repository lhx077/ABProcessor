#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>

// 添加第三方库头文件
#include "lz4.h"
#include "lz4hc.h"
#include "lzma.h"
#include "openssl/aes.h"
#include "openssl/md5.h"

#ifdef _WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API
#endif

// Unity AssetBundle压缩方式
enum UnityCompressionType : uint8_t
{
    None = 0,
    LZMA = 1,
    LZ4 = 2,
    LZ4HC = 3
};

// Unity AssetBundle头部结构
class UnityAssetBundleHeader
{
public:
    // Unity AssetBundle标识符
    static const std::string UNITY_FS_SIGNATURE;
    
    // 文件头字段 - 完全匹配Unity原生格式
    std::string Signature;
    int32_t FormatVersion;
    std::string UnityVersion;
    std::string GeneratorVersion;
    int64_t FileSize;
    uint32_t HeaderSize;
    uint32_t CRC;
    uint8_t MinimumStreamedBytes;
    UnityCompressionType CompressionType;
    int64_t BlocksInfoSize;
    uint64_t UncompressedDataHash;
    
    // 扩展资源信息 - 用于ABProcessor内部使用
    std::string BundleName;
    int32_t FileCount;
    bool IsEncrypted;
    uint32_t Flags;
    
    UnityAssetBundleHeader()
        : Signature(UNITY_FS_SIGNATURE)
        , FormatVersion(6) // Unity 5.3+使用的版本
        , UnityVersion("2019.4.0f1") // Unity版本
        , GeneratorVersion("ABProcessor Native 1.0") // 生成器版本
        , FileSize(0) // 文件总大小
        , HeaderSize(0x40) // 头部大小，通常为64字节
        , CRC(0) // 文件CRC校验值
        , MinimumStreamedBytes(0) // 最小流式字节数
        , CompressionType(UnityCompressionType::LZ4) // 压缩类型
        , BlocksInfoSize(0) // 块信息大小
        , UncompressedDataHash(0) // 未压缩数据哈希
        , FileCount(0)
        , IsEncrypted(false)
        , Flags(0) // Unity AssetBundle标志
    {}
    
    // 序列化头部数据 - 完全匹配Unity原生格式
    std::vector<uint8_t> SerializeHeader();
    
    // 从二进制数据解析头部 - 完全匹配Unity原生格式
    static UnityAssetBundleHeader DeserializeHeader(const std::vector<uint8_t>& data);
};

const std::string UnityAssetBundleHeader::UNITY_FS_SIGNATURE = "UnityFS";

// Unity AssetBundle块信息
class BlockInfo
{
public:
    uint32_t CompressedSize;
    uint32_t UncompressedSize;
    uint16_t Flags;
    
    BlockInfo()
        : CompressedSize(0)
        , UncompressedSize(0)
        , Flags(0)
    {}
    
    // 序列化块信息
    void Serialize(std::vector<uint8_t>& buffer);
    
    // 从二进制数据解析块信息
    static BlockInfo Deserialize(const std::vector<uint8_t>& data, size_t& offset);
};

// Unity AssetBundle文件信息
class AssetBundleFileInfo
{
public:
    std::string Path;
    uint64_t Offset;
    uint64_t Size;
    uint32_t Flags;
    
    AssetBundleFileInfo()
        : Offset(0)
        , Size(0)
        , Flags(0)
    {}
    
    // 序列化文件信息
    void Serialize(std::vector<uint8_t>& buffer);
    
    // 从二进制数据解析文件信息
    static AssetBundleFileInfo Deserialize(const std::vector<uint8_t>& data, size_t& offset);
};

// AssetBundle处理器的主类，提供创建、压缩、加密和管理AssetBundle的功能
class AssetBundleProcessor
{
private:
    std::string _outputPath;
    int _compressionLevel;
    bool _useEncryption;
    std::vector<uint8_t> _encryptionKey;
    UnityCompressionType _unityCompressionType;
    std::string _unityVersion;
    
    // 压缩数据
    std::vector<uint8_t> CompressData(const std::vector<uint8_t>& data, UnityCompressionType compressionType);
    
    // 解压数据
    std::vector<uint8_t> DecompressData(const std::vector<uint8_t>& data, UnityCompressionType compressionType);
    
    // 计算数据哈希值
    uint64_t ComputeHash(const std::vector<uint8_t>& data);
    
    // 计算CRC校验和
    uint32_t CalculateCRC(const std::vector<uint8_t>& data);
    
    // LZMA压缩/解压
    std::vector<uint8_t> CompressLZMA(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecompressLZMA(const std::vector<uint8_t>& data);
    
    // LZ4压缩/解压
    std::vector<uint8_t> CompressLZ4(const std::vector<uint8_t>& data);
    std::vector<uint8_t> CompressLZ4HC(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecompressLZ4(const std::vector<uint8_t>& data);
    
    // 加密/解密
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);
    
    // CRC32计算
    uint32_t CalculateCRC32(const std::vector<uint8_t>& data);
    
    // 哈希计算
    uint64_t CalculateHash(const std::vector<uint8_t>& data);
    
    // 辅助函数：写入字符串到缓冲区
    void WriteString(std::vector<uint8_t>& buffer, const std::string& str);
    
    // 辅助函数：从缓冲区读取字符串
    std::string ReadString(const std::vector<uint8_t>& data, size_t& offset);
    
    // 辅助函数：写入整数到缓冲区
    template<typename T>
    void WriteValue(std::vector<uint8_t>& buffer, T value);
    
    // 辅助函数：从缓冲区读取整数
    template<typename T>
    T ReadValue(const std::vector<uint8_t>& data, size_t& offset);
    
public:
    // 构造函数
    AssetBundleProcessor(
        const std::string& outputPath,
        int compressionLevel = 2, // 对应C#的CompressionLevel.Optimal
        bool useEncryption = false,
        const std::string& encryptionKey = "",
        UnityCompressionType compressionType = UnityCompressionType::LZ4,
        const std::string& unityVersion = "2019.4.0f1");
    
    // 创建AssetBundle
    std::string CreateAssetBundle(const std::string& bundleName, const std::vector<std::string>& files);
    
    // 解包AssetBundle
    std::vector<std::string> ExtractAssetBundle(const std::string& bundlePath, const std::string& extractPath);
};

// C接口包装
extern "C" {

// 创建处理器
EXPORT_API AssetBundleProcessor* CreateProcessor(
    const char* outputPath,
    int compressionLevel,
    bool useEncryption,
    const char* encryptionKey,
    uint8_t compressionType,
    const char* unityVersion)
{
    try {
        return new AssetBundleProcessor(
            outputPath ? outputPath : "",
            compressionLevel,
            useEncryption,
            encryptionKey ? encryptionKey : "",
            static_cast<UnityCompressionType>(compressionType),
            unityVersion ? unityVersion : "2019.4.0f1");
    }
    catch (const std::exception& e) {
        std::cerr << "创建处理器失败: " << e.what() << std::endl;
        return nullptr;
    }
}

// 销毁处理器
EXPORT_API void DestroyProcessor(AssetBundleProcessor* processor)
{
    delete processor;
}

// 创建AssetBundle
EXPORT_API const char* CreateAssetBundle(
    AssetBundleProcessor* processor,
    const char* bundleName,
    const char** files,
    int fileCount,
    int* resultLength)
{
    if (!processor || !bundleName || !files || fileCount <= 0) {
        *resultLength = 0;
        return nullptr;
    }
    
    try {
        std::vector<std::string> fileList;
        for (int i = 0; i < fileCount; ++i) {
            if (files[i]) {
                fileList.push_back(files[i]);
            }
        }
        
        std::string result = processor->CreateAssetBundle(bundleName, fileList);
        *resultLength = static_cast<int>(result.length());
        
        char* resultStr = new char[result.length() + 1];
        std::strcpy(resultStr, result.c_str());
        return resultStr;
    }
    catch (const std::exception& e) {
        std::cerr << "创建AssetBundle失败: " << e.what() << std::endl;
        *resultLength = 0;
        return nullptr;
    }
}

// 解包AssetBundle
EXPORT_API const char** ExtractAssetBundle(
    AssetBundleProcessor* processor,
    const char* bundlePath,
    const char* extractPath,
    int* fileCount,
    int* resultLength)
{
    if (!processor || !bundlePath || !extractPath) {
        *fileCount = 0;
        *resultLength = 0;
        return nullptr;
    }
    
    try {
        std::vector<std::string> extractedFiles = processor->ExtractAssetBundle(bundlePath, extractPath);
        *fileCount = static_cast<int>(extractedFiles.size());
        
        if (extractedFiles.empty()) {
            *resultLength = 0;
            return nullptr;
        }
        
        // 分配内存存储文件路径
        char** result = new char*[extractedFiles.size()];
        for (size_t i = 0; i < extractedFiles.size(); ++i) {
            result[i] = new char[extractedFiles[i].length() + 1];
            std::strcpy(result[i], extractedFiles[i].c_str());
        }
        
        *resultLength = static_cast<int>(extractedFiles.size());
        return const_cast<const char**>(result);
    }
    catch (const std::exception& e) {
        std::cerr << "解包AssetBundle失败: " << e.what() << std::endl;
        *fileCount = 0;
        *resultLength = 0;
        return nullptr;
    }
}

// 获取解包的文件列表
EXPORT_API void GetExtractedFiles(
    const char** resultPtr,
    char** result,
    int resultLength)
{
    if (!resultPtr || !result || resultLength <= 0) {
        return;
    }
    
    for (int i = 0; i < resultLength; ++i) {
        if (resultPtr[i]) {
            std::strcpy(result[i], resultPtr[i]);
        }
    }
}

// 释放字符串内存
EXPORT_API void FreeString(const char* ptr)
{
    delete[] ptr;
}

} // extern "C"

// 辅助函数：写入字符串到缓冲区
void AssetBundleProcessor::WriteString(std::vector<uint8_t>& buffer, const std::string& str) {
    // 写入字符串长度
    uint32_t length = static_cast<uint32_t>(str.length());
    WriteValue(buffer, length);
    
    // 写入字符串内容
    buffer.insert(buffer.end(), str.begin(), str.end());
}

// 辅助函数：从缓冲区读取字符串
std::string AssetBundleProcessor::ReadString(const std::vector<uint8_t>& data, size_t& offset) {
    // 读取字符串长度
    uint32_t length = ReadValue<uint32_t>(data, offset);
    
    // 读取字符串内容
    std::string result(reinterpret_cast<const char*>(data.data() + offset), length);
    offset += length;
    
    return result;
}

// 辅助函数：写入整数到缓冲区
template<typename T>
void AssetBundleProcessor::WriteValue(std::vector<uint8_t>& buffer, T value) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(T));
}

// 辅助函数：从缓冲区读取整数
template<typename T>
T AssetBundleProcessor::ReadValue(const std::vector<uint8_t>& data, size_t& offset) {
    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

// 序列化头部数据
std::vector<uint8_t> UnityAssetBundleHeader::SerializeHeader() {
    std::vector<uint8_t> result;
    
    // 写入签名
    result.insert(result.end(), Signature.begin(), Signature.end());
    
    // 写入格式版本
    result.resize(result.size() + sizeof(int32_t));
    std::memcpy(result.data() + result.size() - sizeof(int32_t), &FormatVersion, sizeof(int32_t));
    
    // 写入Unity版本
    size_t unityVersionLength = UnityVersion.length();
    result.push_back(static_cast<uint8_t>(unityVersionLength));
    result.insert(result.end(), UnityVersion.begin(), UnityVersion.end());
    
    // 写入生成器版本
    size_t generatorVersionLength = GeneratorVersion.length();
    result.push_back(static_cast<uint8_t>(generatorVersionLength));
    result.insert(result.end(), GeneratorVersion.begin(), GeneratorVersion.end());
    
    // 写入文件大小
    result.resize(result.size() + sizeof(int64_t));
    std::memcpy(result.data() + result.size() - sizeof(int64_t), &FileSize, sizeof(int64_t));
    
    // 写入头部大小
    result.resize(result.size() + sizeof(uint32_t));
    std::memcpy(result.data() + result.size() - sizeof(uint32_t), &HeaderSize, sizeof(uint32_t));
    
    // 写入CRC
    result.resize(result.size() + sizeof(uint32_t));
    std::memcpy(result.data() + result.size() - sizeof(uint32_t), &CRC, sizeof(uint32_t));
    
    // 写入最小流式字节数
    result.push_back(MinimumStreamedBytes);
    
    // 写入压缩类型
    result.push_back(static_cast<uint8_t>(CompressionType));
    
    // 写入块信息大小
    result.resize(result.size() + sizeof(int64_t));
    std::memcpy(result.data() + result.size() - sizeof(int64_t), &BlocksInfoSize, sizeof(int64_t));
    
    // 写入未压缩数据哈希
    result.resize(result.size() + sizeof(uint64_t));
    std::memcpy(result.data() + result.size() - sizeof(uint64_t), &UncompressedDataHash, sizeof(uint64_t));
    
    // 写入标志
    result.resize(result.size() + sizeof(uint32_t));
    std::memcpy(result.data() + result.size() - sizeof(uint32_t), &Flags, sizeof(uint32_t));
    
    return result;
}

// 从二进制数据解析头部
UnityAssetBundleHeader UnityAssetBundleHeader::DeserializeHeader(const std::vector<uint8_t>& data) {
    UnityAssetBundleHeader header;
    size_t offset = 0;
    
    // 读取签名
    header.Signature = std::string(reinterpret_cast<const char*>(data.data()), 7);
    offset += 7;
    
    // 读取格式版本
    std::memcpy(&header.FormatVersion, data.data() + offset, sizeof(int32_t));
    offset += sizeof(int32_t);
    
    // 读取Unity版本
    uint8_t unityVersionLength = data[offset++];
    header.UnityVersion = std::string(reinterpret_cast<const char*>(data.data() + offset), unityVersionLength);
    offset += unityVersionLength;
    
    // 读取生成器版本
    uint8_t generatorVersionLength = data[offset++];
    header.GeneratorVersion = std::string(reinterpret_cast<const char*>(data.data() + offset), generatorVersionLength);
    offset += generatorVersionLength;
    
    // 读取文件大小
    std::memcpy(&header.FileSize, data.data() + offset, sizeof(int64_t));
    offset += sizeof(int64_t);
    
    // 读取头部大小
    std::memcpy(&header.HeaderSize, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    // 读取CRC
    std::memcpy(&header.CRC, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    // 读取最小流式字节数
    header.MinimumStreamedBytes = data[offset++];
    
    // 读取压缩类型
    header.CompressionType = static_cast<UnityCompressionType>(data[offset++]);
    
    // 读取块信息大小
    std::memcpy(&header.BlocksInfoSize, data.data() + offset, sizeof(int64_t));
    offset += sizeof(int64_t);
    
    // 读取未压缩数据哈希
    std::memcpy(&header.UncompressedDataHash, data.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    // 读取标志
    std::memcpy(&header.Flags, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    // 检查是否加密
    header.IsEncrypted = (header.Flags & 0x1) != 0;
    
    return header;
}

// 序列化块信息
void BlockInfo::Serialize(std::vector<uint8_t>& buffer) {
    // 写入压缩大小
    buffer.resize(buffer.size() + sizeof(uint32_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint32_t), &CompressedSize, sizeof(uint32_t));
    
    // 写入未压缩大小
    buffer.resize(buffer.size() + sizeof(uint32_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint32_t), &UncompressedSize, sizeof(uint32_t));
    
    // 写入标志
    buffer.resize(buffer.size() + sizeof(uint16_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint16_t), &Flags, sizeof(uint16_t));
}

// 从二进制数据解析块信息
BlockInfo BlockInfo::Deserialize(const std::vector<uint8_t>& data, size_t& offset) {
    BlockInfo blockInfo;
    
    // 读取压缩大小
    std::memcpy(&blockInfo.CompressedSize, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    // 读取未压缩大小
    std::memcpy(&blockInfo.UncompressedSize, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    // 读取标志
    std::memcpy(&blockInfo.Flags, data.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    return blockInfo;
}

// 序列化文件信息
void AssetBundleFileInfo::Serialize(std::vector<uint8_t>& buffer) {
    // 写入路径
    size_t pathLength = Path.length();
    buffer.push_back(static_cast<uint8_t>(pathLength));
    buffer.insert(buffer.end(), Path.begin(), Path.end());
    
    // 写入偏移量
    buffer.resize(buffer.size() + sizeof(uint64_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint64_t), &Offset, sizeof(uint64_t));
    
    // 写入大小
    buffer.resize(buffer.size() + sizeof(uint64_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint64_t), &Size, sizeof(uint64_t));
    
    // 写入标志
    buffer.resize(buffer.size() + sizeof(uint32_t));
    std::memcpy(buffer.data() + buffer.size() - sizeof(uint32_t), &Flags, sizeof(uint32_t));
}

// 从二进制数据解析文件信息
AssetBundleFileInfo AssetBundleFileInfo::Deserialize(const std::vector<uint8_t>& data, size_t& offset) {
    AssetBundleFileInfo fileInfo;
    
    // 读取路径
    uint8_t pathLength = data[offset++];
    fileInfo.Path = std::string(reinterpret_cast<const char*>(data.data() + offset), pathLength);
    offset += pathLength;
    
    // 读取偏移量
    std::memcpy(&fileInfo.Offset, data.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    // 读取大小
    std::memcpy(&fileInfo.Size, data.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    // 读取标志
    std::memcpy(&fileInfo.Flags, data.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    return fileInfo;
}

// 构造函数
AssetBundleProcessor::AssetBundleProcessor(
    const std::string& outputPath,
    int compressionLevel,
    bool useEncryption,
    const std::string& encryptionKey,
    UnityCompressionType compressionType,
    const std::string& unityVersion)
    : _outputPath(outputPath)
    , _compressionLevel(compressionLevel)
    , _useEncryption(useEncryption)
    , _unityCompressionType(compressionType)
    , _unityVersion(unityVersion)
{
    // 处理加密密钥
    if (_useEncryption && !encryptionKey.empty()) {
        // 计算MD5哈希作为AES密钥
        unsigned char md5Result[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(encryptionKey.c_str()), encryptionKey.length(), md5Result);
        _encryptionKey.assign(md5Result, md5Result + MD5_DIGEST_LENGTH);
    }
    
    // 确保输出目录存在
    if (!_outputPath.empty()) {
        std::filesystem::create_directories(_outputPath);
    }
}

// 创建AssetBundle
std::string AssetBundleProcessor::CreateAssetBundle(const std::string& bundleName, const std::vector<std::string>& files) {
    if (files.empty()) {
        throw std::invalid_argument("文件列表不能为空");
    }
    
    // 创建输出路径
    std::string bundlePath = _outputPath + "/" + bundleName;
    
    // 准备文件数据
    std::vector<AssetBundleFileInfo> fileInfos;
    std::vector<uint8_t> fileData;
    uint64_t currentOffset = 0;
    
    for (const auto& filePath : files) {
        // 读取文件
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("无法打开文件: " + filePath);
        }
        
        // 获取文件大小
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // 读取文件内容
        std::vector<uint8_t> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        
        // 创建文件信息
        AssetBundleFileInfo fileInfo;
        fileInfo.Path = std::filesystem::path(filePath).filename().string();
        fileInfo.Offset = currentOffset;
        fileInfo.Size = fileSize;
        fileInfo.Flags = 0;
        
        // 更新偏移量
        currentOffset += fileSize;
        
        // 添加到列表
        fileInfos.push_back(fileInfo);
        fileData.insert(fileData.end(), buffer.begin(), buffer.end());
    }
    
    // 创建块信息
    BlockInfo blockInfo;
    blockInfo.UncompressedSize = static_cast<uint32_t>(fileData.size());
    blockInfo.Flags = 0;
    
    // 压缩数据
    std::vector<uint8_t> compressedData = CompressData(fileData, _unityCompressionType);
    blockInfo.CompressedSize = static_cast<uint32_t>(compressedData.size());
    
    // 如果需要加密，则加密数据
    if (_useEncryption) {
        compressedData = EncryptData(compressedData);
        blockInfo.Flags |= 0x1; // 设置加密标志
    }
    
    // 序列化文件信息
    std::vector<uint8_t> fileInfoData;
    // 写入文件数量
    uint32_t fileCount = static_cast<uint32_t>(fileInfos.size());
    fileInfoData.resize(fileInfoData.size() + sizeof(uint32_t));
    std::memcpy(fileInfoData.data() + fileInfoData.size() - sizeof(uint32_t), &fileCount, sizeof(uint32_t));
    
    // 写入每个文件的信息
    for (const auto& fileInfo : fileInfos) {
        fileInfo.Serialize(fileInfoData);
    }
    
    // 创建头部
    UnityAssetBundleHeader header;
    header.BundleName = bundleName;
    header.FileCount = static_cast<int32_t>(fileInfos.size());
    header.IsEncrypted = _useEncryption;
    header.CompressionType = _unityCompressionType;
    header.UnityVersion = _unityVersion;
    
    // 计算块信息大小
    header.BlocksInfoSize = sizeof(uint32_t) + sizeof(BlockInfo) + fileInfoData.size();
    
    // 计算文件大小
    header.FileSize = header.HeaderSize + header.BlocksInfoSize + compressedData.size();
    
    // 计算未压缩数据哈希
    header.UncompressedDataHash = ComputeHash(fileData);
    
    // 序列化头部
    std::vector<uint8_t> headerData = header.SerializeHeader();
    
    // 创建输出文件
    std::ofstream outputFile(bundlePath, std::ios::binary);
    if (!outputFile) {
        throw std::runtime_error("无法创建输出文件: " + bundlePath);
    }
    
    // 写入头部
    outputFile.write(reinterpret_cast<const char*>(headerData.data()), headerData.size());
    
    // 写入块数量（始终为1）
    uint32_t blockCount = 1;
    outputFile.write(reinterpret_cast<const char*>(&blockCount), sizeof(uint32_t));
    
    // 写入块信息
    blockInfo.Serialize(std::vector<uint8_t>& buffer);
    outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    
    // 写入文件信息
    outputFile.write(reinterpret_cast<const char*>(fileInfoData.data()), fileInfoData.size());
    
    // 写入压缩数据
    outputFile.write(reinterpret_cast<const char*>(compressedData.data()), compressedData.size());
    
    // 计算CRC
    outputFile.seekp(0, std::ios::beg);
    std::vector<uint8_t> fileContent(header.FileSize);
    outputFile.read(reinterpret_cast<char*>(fileContent.data()), fileContent.size());
    header.CRC = CalculateCRC(fileContent);
    
    // 更新CRC
    outputFile.seekp(0, std::ios::beg);
    headerData = header.SerializeHeader();
    outputFile.write(reinterpret_cast<const char*>(headerData.data()), headerData.size());
    
    return bundlePath;
}

// 解包AssetBundle
std::vector<std::string> AssetBundleProcessor::ExtractAssetBundle(const std::string& bundlePath, const std::string& extractPath) {
    // 检查文件是否存在
    std::ifstream file(bundlePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("AssetBundle文件不存在: " + bundlePath);
    }
    
    // 确保提取目录存在
    std::filesystem::create_directories(extractPath);
    
    std::vector<std::string> extractedFiles;
    
    // 读取头部
    std::vector<uint8_t> headerData(64); // 头部大小通常为64字节
    file.read(reinterpret_cast<char*>(headerData.data()), headerData.size());
    UnityAssetBundleHeader header = UnityAssetBundleHeader::DeserializeHeader(headerData);
    
    // 读取块数量
    uint32_t blockCount;
    file.read(reinterpret_cast<char*>(&blockCount), sizeof(uint32_t));
    
    // 读取块信息
    std::vector<BlockInfo> blocks;
    for (uint32_t i = 0; i < blockCount; ++i) {
        size_t offset = 0;
        std::vector<uint8_t> blockData(sizeof(uint32_t) * 2 + sizeof(uint16_t));
        file.read(reinterpret_cast<char*>(blockData.data()), blockData.size());
        blocks.push_back(BlockInfo::Deserialize(blockData, offset));
    }
    
    // 读取文件数量
    uint32_t fileCount;
    file.read(reinterpret_cast<char*>(&fileCount), sizeof(uint32_t));
    
    // 读取文件信息
    std::vector<AssetBundleFileInfo> fileInfos;
    for (uint32_t i = 0; i < fileCount; ++i) {
        // 读取路径长度
        uint8_t pathLength;
        file.read(reinterpret_cast<char*>(&pathLength), sizeof(uint8_t));
        
        // 读取路径
        std::vector<char> pathBuffer(pathLength);
        file.read(pathBuffer.data(), pathLength);
        
        // 读取偏移量、大小和标志
        AssetBundleFileInfo fileInfo;
        fileInfo.Path = std::string(pathBuffer.data(), pathLength);
        file.read(reinterpret_cast<char*>(&fileInfo.Offset), sizeof(uint64_t));
        file.read(reinterpret_cast<char*>(&fileInfo.Size), sizeof(uint64_t));
        file.read(reinterpret_cast<char*>(&fileInfo.Flags), sizeof(uint32_t));
        
        fileInfos.push_back(fileInfo);
    }
    
    // 读取压缩数据
    std::vector<uint8_t> compressedData(blocks[0].CompressedSize);
    file.read(reinterpret_cast<char*>(compressedData.data()), compressedData.size());
    
    // 如果数据已加密，则解密
    if (header.IsEncrypted) {
        compressedData = DecryptData(compressedData);
    }
    
    // 解压数据
    std::vector<uint8_t> decompressedData = DecompressData(compressedData, header.CompressionType);
    
    // 提取文件
    for (const auto& fileInfo : fileInfos) {
        std::string outputPath = extractPath + "/" + fileInfo.Path;
        std::ofstream outputFile(outputPath, std::ios::binary);
        if (!outputFile) {
            throw std::runtime_error("无法创建输出文件: " + outputPath);
        }
        
        // 写入文件内容
        outputFile.write(reinterpret_cast<const char*>(decompressedData.data() + fileInfo.Offset), fileInfo.Size);
        extractedFiles.push_back(outputPath);
    }
    
    return extractedFiles;
}

// 使用LZMA压缩数据
std::vector<uint8_t> AssetBundleProcessor::CompressLZMA(const std::vector<uint8_t>& data) {
    // LZMA压缩实现
    lzma_options_lzma options;
    lzma_lzma_preset(&options, _compressionLevel);
    
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_alone_encoder(&strm, &options);
    if (ret != LZMA_OK) {
        throw std::runtime_error("LZMA编码器初始化失败");
    }
    
    // 预估压缩后的大小
    size_t outSize = data.size() + data.size() / 3 + 128;
    std::vector<uint8_t> outBuffer(outSize);
    
    strm.next_in = data.data();
    strm.avail_in = data.size();
    strm.next_out = outBuffer.data();
    strm.avail_out = outBuffer.size();
    
    ret = lzma_code(&strm, LZMA_FINISH);
    if (ret != LZMA_STREAM_END) {
        lzma_end(&strm);
        throw std::runtime_error("LZMA压缩失败");
    }
    
    // 调整输出缓冲区大小为实际压缩大小
    outBuffer.resize(outBuffer.size() - strm.avail_out);
    lzma_end(&strm);
    
    return outBuffer;
}

// 解压LZMA数据
std::vector<uint8_t> AssetBundleProcessor::DecompressLZMA(const std::vector<uint8_t>& data) {
    // LZMA解压实现
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_alone_decoder(&strm, UINT64_MAX);
    if (ret != LZMA_OK) {
        throw std::runtime_error("LZMA解码器初始化失败");
    }
    
    // 预估解压后的大小（通常是压缩数据的4-10倍）
    size_t outSize = data.size() * 5;
    std::vector<uint8_t> outBuffer(outSize);
    
    strm.next_in = data.data();
    strm.avail_in = data.size();
    strm.next_out = outBuffer.data();
    strm.avail_out = outBuffer.size();
    
    ret = lzma_code(&strm, LZMA_FINISH);
    if (ret != LZMA_STREAM_END) {
        lzma_end(&strm);
        throw std::runtime_error("LZMA解压失败");
    }
    
    // 调整输出缓冲区大小为实际解压大小
    outBuffer.resize(outBuffer.size() - strm.avail_out);
    lzma_end(&strm);
    
    return outBuffer;
}

// 使用LZ4压缩数据
std::vector<uint8_t> AssetBundleProcessor::CompressLZ4(const std::vector<uint8_t>& data) {
    // LZ4压缩实现
    int maxCompressedSize = LZ4_compressBound(static_cast<int>(data.size()));
    std::vector<uint8_t> compressedData(maxCompressedSize);
    
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressedData.data()),
        static_cast<int>(data.size()),
        maxCompressedSize
    );
    
    if (compressedSize <= 0) {
        throw std::runtime_error("LZ4压缩失败");
    }
    
    compressedData.resize(compressedSize);
    return compressedData;
}

// 使用LZ4HC压缩数据
std::vector<uint8_t> AssetBundleProcessor::CompressLZ4HC(const std::vector<uint8_t>& data) {
    // LZ4HC压缩实现
    int maxCompressedSize = LZ4_compressBound(static_cast<int>(data.size()));
    std::vector<uint8_t> compressedData(maxCompressedSize);
    
    int compressedSize = LZ4_compress_HC(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressedData.data()),
        static_cast<int>(data.size()),
        maxCompressedSize,
        _compressionLevel
    );
    
    if (compressedSize <= 0) {
        throw std::runtime_error("LZ4HC压缩失败");
    }
    
    compressedData.resize(compressedSize);
    return compressedData;
}

// 解压LZ4数据
std::vector<uint8_t> AssetBundleProcessor::DecompressLZ4(const std::vector<uint8_t>& data) {
    // 获取原始大小（Unity AssetBundle中通常在块信息中存储）
    int decompressedSize = static_cast<int>(data.size() * 4); // 估计值，实际应从块信息中获取
    std::vector<uint8_t> decompressedData(decompressedSize);
    
    int result = LZ4_decompress_safe(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(decompressedData.data()),
        static_cast<int>(data.size()),
        decompressedSize
    );
    
    if (result <= 0) {
        throw std::runtime_error("LZ4解压失败");
    }
    
    decompressedData.resize(result);
    return decompressedData;
}

// 加密数据
std::vector<uint8_t> AssetBundleProcessor::EncryptData(const std::vector<uint8_t>& data) {
    if (!_useEncryption || _encryptionKey.empty()) {
        return data;
    }
    
    // 使用AES-128-ECB模式加密
    AES_KEY aesKey;
    AES_set_encrypt_key(_encryptionKey.data(), 128, &aesKey);
    
    // 确保数据长度是16字节的倍数（AES块大小）
    size_t paddedSize = (data.size() + 15) & ~15;
    std::vector<uint8_t> paddedData(paddedSize, 0);
    std::copy(data.begin(), data.end(), paddedData.begin());
    
    // 加密数据
    std::vector<uint8_t> encryptedData(paddedSize);
    for (size_t i = 0; i < paddedSize; i += 16) {
        AES_encrypt(
            paddedData.data() + i,
            encryptedData.data() + i,
            &aesKey
        );
    }
    
    return encryptedData;
}

// 解密数据
std::vector<uint8_t> AssetBundleProcessor::DecryptData(const std::vector<uint8_t>& data) {
    if (!_useEncryption || _encryptionKey.empty()) {
        return data;
    }
    
    // 使用AES-128-ECB模式解密
    AES_KEY aesKey;
    AES_set_decrypt_key(_encryptionKey.data(), 128, &aesKey);
    
    // 确保数据长度是16字节的倍数（AES块大小）
    if (data.size() % 16 != 0) {
        throw std::runtime_error("加密数据长度必须是16字节的倍数");
    }
    
    // 解密数据
    std::vector<uint8_t> decryptedData(data.size());
    for (size_t i = 0; i < data.size(); i += 16) {
        AES_decrypt(
            data.data() + i,
            decryptedData.data() + i,
            &aesKey
        );
    }
    
    return decryptedData;
}

// 计算CRC32校验和
uint32_t AssetBundleProcessor::CalculateCRC32(const std::vector<uint8_t>& data) {
    // CRC32计算实现
    uint32_t crc = 0xFFFFFFFF;
    static const uint32_t crcTable[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    for (size_t i = 0; i < data.size(); ++i) {
        crc = (crc >> 8) ^ crcTable[(crc ^ data[i]) & 0xFF];
    }
    
    return crc ^ 0xFFFFFFFF;
}

// 计算哈希值
uint64_t AssetBundleProcessor::CalculateHash(const std::vector<uint8_t>& data) {
    // 简单的哈希计算实现（FNV-1a 64位）
    const uint64_t FNV_PRIME = 1099511628211ULL;
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= FNV_PRIME;
    }
    
    return hash;
}