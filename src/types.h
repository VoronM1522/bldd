#include <elf.h>


typedef union ElfN_Ehdr {
    Elf64_Ehdr ehdr64;
    Elf32_Ehdr ehdr32;
} ElfN_Ehdr;

typedef union ElfN_Phdr {
    Elf64_Phdr phdr64;
    Elf32_Phdr phdr32;
} ElfN_Phdr;

typedef union ElfN_Shdr {
    Elf64_Shdr shdr64;
    Elf32_Shdr shdr32;
} ElfN_Shdr;

typedef union ElfN_Addr {
    Elf64_Addr addr64;
    Elf32_Addr addr32;
} ElfN_Addr;

typedef union ElfN_Off {
    Elf64_Off off64;
    Elf32_Off off32;
} ElfN_Off;

typedef union ElfN_Word {
    Elf64_Word word64;
    Elf32_Word word32;
} ElfN_Word;

typedef union ElfN_Half {
    Elf64_Half half64;
    Elf32_Half half32;
} ElfN_Half;

typedef union ElfN_Dyn {
    Elf64_Dyn dyn64;
    Elf32_Dyn dyn32;
} ElfN_Dyn;

typedef union uintN_t {
    uint64_t uint64;
    uint32_t uint32;
} uintN_t;
