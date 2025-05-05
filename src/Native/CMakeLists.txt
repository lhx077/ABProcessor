cmake_minimum_required(VERSION 3.15)
project(ABProcessorNative)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖包
find_package(LZMA REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(lz4 CONFIG REQUIRED)

# 设置源文件
set(SOURCE_FILES 
    src/ABProcessorNative.cpp)

# 创建动态库
add_library(ABProcessorNative SHARED ${SOURCE_FILES})

# 设置依赖库
target_include_directories(ABProcessorNative PRIVATE 
    ${LZMA_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR})

# 链接依赖库
target_link_libraries(ABProcessorNative PRIVATE 
    LZMA::LZMA
    OpenSSL::SSL
    OpenSSL::Crypto
    lz4::lz4)

# 定义导出宏
target_compile_definitions(ABProcessorNative PRIVATE 
    -DEXPORT_API=__declspec\(dllexport\))

# 安装规则
install(TARGETS ABProcessorNative
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib) 