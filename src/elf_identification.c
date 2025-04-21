#include <stdio.h>
#include <stdbool.h>
#include "types.h"

#define MIN(a, b) ({ \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    (void) (&_a == &_b); \
    _a < _b ? _a : _b; \
})


ElfN_Ehdr* identificate_elf(int fd, int size, char* name, bool verbose) {
    ElfN_Ehdr* elf_header = NULL;
    uint16_t e_ehsize = 0;
    unsigned char e_ident[EI_NIDENT];

    if (size < EI_NIDENT) {
        if (verbose) {
            printf("%s: File if too small!\n", name);
        }

        return elf_header;
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
        fprintf(stderr, "%s: Cannot set offset 0\n", name);
        return elf_header;
    }

    if (read(fd, e_ident, EI_NIDENT) != EI_NIDENT) {
        if (verbose) {
            printf("%s: Cannot read the file!\n", name);
        }
        
        return elf_header;
    }

    if ( \
        e_ident[EI_MAG0] != ELFMAG0 || \
        e_ident[EI_MAG1] != ELFMAG1 || \
        e_ident[EI_MAG2] != ELFMAG2 || \
        e_ident[EI_MAG3] != ELFMAG3 || \
        /* e_ident[EI_CLASS] != ELFCLASSNONE && \ */ 
        e_ident[EI_CLASS] != ELFCLASS32 && \
        e_ident[EI_CLASS] != ELFCLASS64 || \
        /* e_ident[EI_DATA] != ELFDATANONE && \ */ 
        e_ident[EI_DATA] != ELFDATA2LSB || \
        /* e_ident[EI_DATA] != ELFDATA2MSB || \ */
        /* e_ident[EI_VERSION] != EV_NONE && \ */
        e_ident[EI_VERSION] != EV_CURRENT \
        /* May also check EI_OSABI, EI_NIDENT, EI_ABIVERSION etc. */
    ) {
        if (verbose) {
            printf("%s: File if not ELF!\n", name);
        }
        
        return elf_header;
    }

    if (lseek(fd, EI_NIDENT + (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(ElfN_Off)) * 2 + sizeof(ElfN_Addr), SEEK_SET) == -1) {
        fprintf(stderr, "%s: Cannot set offset\n", name);
        return elf_header;
    }

    if (read(fd, &e_ehsize, sizeof(uint16_t)) != sizeof(uint16_t)) {
        if (verbose) {
            printf("%s: Cannot read the file!\n", name);
        }
        
        return elf_header;
    }

    if (e_ehsize > size) {
        if (verbose) {
            printf("%s: File if not ELF!\n", name);
        }
        
        return elf_header;
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
        fprintf(stderr, "%s: Cannot set offset 0\n", name);
        return elf_header;
    }

    if (e_ident[EI_CLASS] == ELFCLASS64) { // ПРОВЕРИТЬ!!!
        elf_header = (ElfN_Ehdr*) safe_calloc(1, sizeof(ElfN_Ehdr)); 

        if (read(fd, elf_header, sizeof(ElfN_Ehdr)) != sizeof(ElfN_Ehdr)) {
            if (verbose) {
                printf("%s: Cannot read the file!\n", name);
            }
            
            return elf_header;
        }
    } else {
        elf_header = (ElfN_Ehdr*) safe_calloc(1, sizeof(Elf32_Ehdr)); 

        if (read(fd, elf_header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
            if (verbose) {
                printf("%s: Cannot read the file!\n", name);
            }
            
            return elf_header;
        }
    }

    return elf_header;
}
