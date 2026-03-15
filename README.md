# Windows TLS 注入技术研究项目

## 1. 项目概述

本项目是一个用于演示 **Windows PE (Portable Executable) 文件 TLS 回调注入技术** 的 C++ 实现。该项目旨在帮助安全研究人员理解 TLS 回调（Thread Local Storage Callback）的工作原理，以及如何在不修改程序入口点（OEP）的情况下实现代码注入和执行。

**核心功能：**
- **PE文件解析**：解析 DOS 头、NT 头、节表（Section Table）和数据目录表（Data Directory）。
- **新增节区注入**：在目标 PE 文件末尾添加一个新的节（Section），用于存放 Shellcode 和伪造的 TLS 数据结构。
- **智能 TLS 处理**：
  - 如果目标文件 **没有** TLS 表：创建全新的 `IMAGE_TLS_DIRECTORY64` 结构，并将其添加到数据目录表中。
  - 如果目标文件 **已有** TLS 表：保留原有回调函数，将新的 Shellcode 地址追加到回调函数数组末尾，实现无损注入。
- **ASLR 处理**：自动禁用动态基址（Dynamic Base），确保硬编码的绝对地址（VA）在运行时有效。

---

## 2. 理论基础：TLS 回调机制

**TLS (Thread Local Storage)** 是 Windows 操作系统提供的一种机制，允许每个线程拥有自己的变量存储空间。

### 为什么 TLS 回调适合注入？
在 Windows 加载器（OS Loader）加载 PE 文件时，**TLS 回调函数会在程序的入口点（Entry Point, OEP）之前执行**。
- 这意味着注入的代码可以先于主程序逻辑运行。
- 常用于反调试（Anti-Debugging）检测、环境检查或恶意代码的隐蔽启动。

### 关键数据结构
在 PE 文件头中，`IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS]` 指向 `IMAGE_TLS_DIRECTORY` 结构体：

```cpp
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;         // TLS 索引的地址
    ULONGLONG AddressOfCallBacks;     // 指向回调函数数组的指针 (重点)
    DWORD     SizeOfZeroFill;
    DWORD     Characteristics;
} IMAGE_TLS_DIRECTORY64;
```

`AddressOfCallBacks` 指向一个以 `0` 结尾的函数指针数组。系统加载器会依次调用数组中的每个函数。

---

## 3. 项目结构说明

- **`injector.cpp`**: 
  - **核心工具**。负责读取目标 PE 文件，计算新节区位置，写入 Shellcode，构建/修改 TLS 目录结构，并生成注入后的可执行文件。
  - [查看代码](injector.cpp)

- **`target.cpp`**:
  - **无 TLS 的目标程序**。一个简单的 "Hello World" 程序，用于测试“从无到有”创建 TLS 表的场景。
  - [查看代码](target.cpp)

- **`target_tls.cpp`**:
  - **带 TLS 的目标程序**。代码中预定义了一个 TLS 回调函数，用于测试“追加注入”保留原有功能的场景。
  - [查看代码](target_tls.cpp)

- **`CMakeLists.txt`**:
  - CMake 构建脚本，用于编译上述所有程序。
  - [查看代码](CMakeLists.txt)

---

## 4. 注入流程详解 (Implementation Details)

`injector.cpp` 的工作流程如下：

1. **文件读取与验证**：
   - 读取目标 PE 文件到内存。
   - 验证 DOS 签名 (`MZ`) 和 NT 签名 (`PE\0\0`)。
   - 检查是否为 64 位程序 (`IMAGE_NT_OPTIONAL_HDR64_MAGIC`)。

2. **添加新节区 (.tlsinj)**：
   - 在节表末尾构造一个新的 `IMAGE_SECTION_HEADER`。
   - 设置属性为 `RWE` (Read | Write | Execute)，确保 Shellcode 可执行且数据可写。
   - 计算新节区的虚拟地址 (VirtualAddress) 和文件偏移 (PointerToRawData)。

3. **Shellcode 植入**：
   - 将准备好的 x64 Shellcode（默认为弹计算器或死循环）写入新节区的开头。

4. **处理 TLS 目录**：
   - **情况 A：目标无 TLS 表**
     - 在新节区中构造一个 `IMAGE_TLS_DIRECTORY64` 结构体。
     - 构造一个回调数组：`{ Shellcode_VA, 0 }`。
     - 将数据目录表 `IMAGE_DIRECTORY_ENTRY_TLS` 指向新构造的结构体。
   - **情况 B：目标有 TLS 表**
     - 解析原有的 TLS 目录，找到原回调数组。
     - 将原数组内容复制到新节区，并在末尾追加我们的 Shellcode 地址。
     - 更新原 TLS 目录的 `AddressOfCallBacks` 指针，使其指向新的数组。

5. **禁用 ASLR**：
   - 修改 `OptionalHeader.DllCharacteristics`，移除 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` 标志。
   - **原因**：TLS 回调数组中存储的是绝对虚拟地址（VA）。如果开启 ASLR，程序加载基址随机化，硬编码的 VA 将失效导致崩溃。

---

## 5. 编译与运行指南

### 环境要求
- Windows 操作系统
- C++ 编译器 (MinGW-w64 或 MSVC)
- CMake

### 编译步骤

```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```

### 测试步骤

1. **生成测试程序**：
   编译后会生成 `target.exe` (无TLS) 和 `target_tls.exe` (有TLS)。

2. **运行注入器**：
   ```bash
   # 用法: injector.exe <目标文件> <输出文件>
   
   # 测试 1: 注入无 TLS 的程序
   ./injector.exe target.exe target_injected.exe
   
   # 测试 2: 注入已有 TLS 的程序
   ./injector.exe target_tls.exe target_tls_injected.exe
   ```

3. **验证结果**：
   运行生成的 `target_injected.exe`。
   - **预期行为**：程序启动时，先弹出一个计算器（或卡住，取决于 Shellcode），关闭计算器后，控制台才输出 "Target Main function executed!"。

---

## 6. 免责声明

本代码仅供 **安全研究与教学使用**。请勿将此技术用于非法用途。开发者不对任何因使用本项目代码而造成的直接或间接后果负责。
