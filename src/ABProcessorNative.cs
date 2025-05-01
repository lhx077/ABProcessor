using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ABProcessor
{
    /// <summary>
    /// ABProcessor的C++原生实现包装类
    /// 提供与C#版本相同的功能，但使用C++实现以获得更高性能
    /// </summary>
    public class ABProcessorNative : IDisposable
    {
        // 定义DLL导入
        private const string DllName = "ABProcessorNative";

        #region Native方法导入

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr CreateProcessor(
            [MarshalAs(UnmanagedType.LPStr)] string outputPath,
            int compressionLevel,
            [MarshalAs(UnmanagedType.I1)] bool useEncryption,
            [MarshalAs(UnmanagedType.LPStr)] string encryptionKey,
            byte compressionType,
            [MarshalAs(UnmanagedType.LPStr)] string unityVersion);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void DestroyProcessor(IntPtr processor);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr CreateAssetBundle(
            IntPtr processor,
            [MarshalAs(UnmanagedType.LPStr)] string bundleName,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] string[] files,
            int fileCount,
            out int resultLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ExtractAssetBundle(
            IntPtr processor,
            [MarshalAs(UnmanagedType.LPStr)] string bundlePath,
            [MarshalAs(UnmanagedType.LPStr)] string extractPath,
            out int fileCount,
            out int resultLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void GetExtractedFiles(
            IntPtr resultPtr,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] string[] result,
            int resultLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void FreeString(IntPtr ptr);

        #endregion

        private IntPtr _nativeProcessor;
        private bool _disposed = false;

        /// <summary>
        /// 初始化ABProcessor的C++原生实现
        /// </summary>
        /// <param name="outputPath">AssetBundle输出路径</param>
        /// <param name="compressionLevel">压缩级别</param>
        /// <param name="useEncryption">是否使用加密</param>
        /// <param name="encryptionKey">加密密钥（如果使用加密）</param>
        /// <param name="compressionType">Unity压缩类型</param>
        /// <param name="unityVersion">目标Unity版本</param>
        public ABProcessorNative(
            string outputPath,
            System.IO.Compression.CompressionLevel compressionLevel = System.IO.Compression.CompressionLevel.Optimal,
            bool useEncryption = false,
            string encryptionKey = null,
            UnityCompressionType compressionType = UnityCompressionType.LZ4,
            string unityVersion = "2019.4.0f1")
        {
            _nativeProcessor = CreateProcessor(
                outputPath,
                (int)compressionLevel,
                useEncryption,
                encryptionKey,
                (byte)compressionType,
                unityVersion);

            if (_nativeProcessor == IntPtr.Zero)
            {
                throw new InvalidOperationException("无法创建原生ABProcessor实例");
            }
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

            string[] fileArray = files.ToArray();
            int resultLength;
            IntPtr resultPtr = CreateAssetBundle(_nativeProcessor, bundleName, fileArray, fileArray.Length, out resultLength);

            if (resultPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("创建AssetBundle失败");
            }

            string result = Marshal.PtrToStringAnsi(resultPtr);
            FreeString(resultPtr);

            return result;
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

            int fileCount;
            int resultLength;
            IntPtr resultPtr = ExtractAssetBundle(_nativeProcessor, bundlePath, extractPath, out fileCount, out resultLength);

            if (resultPtr == IntPtr.Zero || fileCount <= 0)
            {
                throw new InvalidOperationException("解包AssetBundle失败");
            }

            string[] extractedFiles = new string[fileCount];
            GetExtractedFiles(resultPtr, extractedFiles, fileCount);
            FreeString(resultPtr);

            return new List<string>(extractedFiles);
        }

        #region IDisposable实现

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        /// <param name="disposing">是否正在释放托管资源</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_nativeProcessor != IntPtr.Zero)
                {
                    DestroyProcessor(_nativeProcessor);
                    _nativeProcessor = IntPtr.Zero;
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// 析构函数
        /// </summary>
        ~ABProcessorNative()
        {
            Dispose(false);
        }

        #endregion
    }
}