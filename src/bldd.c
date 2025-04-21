#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h> 
#include "safe.c"
#include "elf_identification.c"


#define MAX_NAME_LEN 256


void* safe_calloc(size_t nmemb, size_t size); /* safe.c */
void* safe_realloc(void *ptr, size_t size); /* safe.c */
void* safe_free(void *ptr); /* safe.c */
ElfN_Ehdr* identificate_elf(int fd, int size, char* name, bool verbose); /* elf_identification.c */


char** bdll(char* name, bool verbose, bool brute) {
    int size = 0;
    int dyn_arr_size = 0;
    int fd = 0;
    uint16_t ph_num = 0;
    uint16_t sh_num = 0;
    uint16_t ph_size = 0;
    uint16_t sh_size = 0;
    // uintN_t dyn_size = 0;
    unsigned int char_counter = 0;
    int lib_counter = 0;
    char** list_of_libs = NULL;
    ElfN_Ehdr* elf_header = NULL;
    ElfN_Phdr* phdr = NULL;
    ElfN_Shdr* shdr = NULL;
    ElfN_Dyn* dyn = NULL;
    struct stat* file_stat = NULL;
    char* lib_name = NULL;
    char* tmp = NULL;
    ElfN_Off* dyn_offest_arr = NULL;
    ElfN_Off ph_offset = {0};
    ElfN_Off sh_offset = {0};
    ElfN_Off prev_offset = {0};
    ElfN_Word dyn_str_offset = {0};
    ElfN_Word lib_name_offset = {0};
    bool repeat = false;
    bool done = false;
    bool arch64 = false;
    bool flag = false;

    if (name == NULL) {
        return list_of_libs;
    }
    

    fd = open(name, O_RDONLY);

    if (fd == -1) {
        if (verbose) {
            fprintf(stderr, "%s: Cannot open the file\n", name);
        }

        goto exit;
    }
    
    file_stat = (struct stat*) safe_calloc(1, sizeof(struct stat));

    if (fstat(fd, file_stat) == -1) {
        file_stat = safe_free(file_stat);

        if (verbose) {
            fprintf(stderr, "%s: Cannot get stat\n", name);
        }

        goto exit;
    }

    size = file_stat->st_size;
    file_stat = safe_free(file_stat);
    elf_header = identificate_elf(fd, size, name, verbose);
    tmp = (char*) elf_header;

    if (elf_header != NULL && tmp[EI_CLASS] == ELFCLASS64) {
        arch64 = true;
    }

    tmp = NULL;

    if (elf_header != NULL) {
        if(arch64) {
            ph_offset.off64 = elf_header->ehdr64.e_phoff;
        } else {
            ph_offset.off32 = elf_header->ehdr32.e_phoff;
        }
        

        if (ph_offset.off64 == 0) { // (ПРОВЕРИТЬ!) Можно оставить так, так как место занято под больший тип данных
            goto shdr_traversal;
        } else if (arch64 && ph_offset.off64 < sizeof(Elf64_Ehdr) || !arch64 && ph_offset.off32 < sizeof(Elf32_Ehdr) || ph_offset.off64 >= size) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_phoff\n", name);
            }

            if (brute) {
                goto shdr_traversal;
            }

            goto exit;
        }

        if(arch64) {
            ph_num = elf_header->ehdr64.e_phnum;
        } else {
            ph_num = elf_header->ehdr32.e_phnum;
        }

        if (ph_num < 0) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_phnum\n", name);
            }

            if (brute) {
                goto shdr_traversal;
            }

            goto exit;
        }

        if(arch64) {
            ph_size = elf_header->ehdr64.e_phentsize;
        } else {
            ph_size = elf_header->ehdr32.e_phentsize;
        }

        if (ph_size < 0) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_phentsize\n", name);
            }

            if (brute) {
                goto shdr_traversal;
            }

            goto exit;
        }       
        

        if(arch64) {
            if (lseek(fd, ph_offset.off64, SEEK_SET) == -1) {
                fprintf(stderr, "%s: Cannot set offset\n", name);
                goto exit;
            }
        } else {
            if (lseek(fd, ph_offset.off32, SEEK_SET) == -1) {
                fprintf(stderr, "%s: Cannot set offset\n", name);
                goto exit;
            }
        }
        

        phdr = (ElfN_Phdr*) safe_calloc(1, ph_size);

        for (int i = 0; i < ph_num; ++i) {
            if (read(fd, phdr, ph_size) != ph_size) {
                fprintf(stderr, "%s: Cannot read the Phdr\n", name);
                goto exit;
            }

            if (arch64 && phdr->phdr64.p_type == PT_DYNAMIC || !arch64 && phdr->phdr32.p_type == PT_DYNAMIC) {
                if ( \
                    arch64 && (phdr->phdr64.p_offset < sizeof(Elf64_Ehdr) || phdr->phdr64.p_offset >= size) || \
                    !arch64 && (phdr->phdr32.p_offset < sizeof(Elf32_Ehdr) || phdr->phdr32.p_offset >= size\
                )) {
                    fprintf(stderr, "%s: Incorrect offset for dynamic segment\n", name);
                    goto exit;
                }

                if (dyn_offest_arr == NULL) {
                    if (arch64) {
                        dyn_offest_arr = (ElfN_Off*) safe_calloc(1, sizeof(Elf64_Off));
                    } else {
                        dyn_offest_arr = (ElfN_Off*) safe_calloc(1, sizeof(Elf32_Off));
                    }
                    
                    ++dyn_arr_size;
                } else {
                    ++dyn_arr_size;

                    if (arch64) {
                        dyn_offest_arr = (ElfN_Off*) safe_realloc(dyn_offest_arr, sizeof(Elf64_Off) * dyn_arr_size);
                    } else {
                        dyn_offest_arr = (ElfN_Off*) safe_realloc(dyn_offest_arr, sizeof(Elf32_Off) * dyn_arr_size);
                    }
                }

                if (arch64) {
                    dyn_offest_arr[dyn_arr_size - 1].off64 = phdr->phdr64.p_offset;
                } else {
                    dyn_offest_arr[dyn_arr_size - 1].off32 = phdr->phdr32.p_offset;
                }
            }
        }

        shdr_traversal:

        if (arch64) {
            sh_offset.off64 = elf_header->ehdr64.e_shoff;
        } else {
            sh_offset.off32 = elf_header->ehdr32.e_shoff;
        }
        

        if (arch64 && sh_offset.off64 == 0 || !arch64 && sh_offset.off32 == 0) {
            goto dynamic_sections_traversal;
        } else if ( \
            arch64 && (sh_offset.off64 < sizeof(Elf64_Ehdr) || sh_offset.off64 >= size) || \
            !arch64 && (sh_offset.off32 < sizeof(Elf32_Ehdr) || sh_offset.off32 >= size) \
        ) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_shoff\n", name);
            }

            if (brute) {
                goto dynamic_sections_traversal;
            }

            goto exit;
        }

        if (arch64) {
            sh_num = elf_header->ehdr64.e_shnum;
        } else {
            sh_num = elf_header->ehdr32.e_shnum;
        }

        if (sh_num < 0) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_shnum\n", name);
            }

            if (brute) {
                goto dynamic_sections_traversal;
            }

            goto exit;
        }

        if (arch64) {
            sh_size = elf_header->ehdr64.e_shentsize;
        } else {
            sh_size = elf_header->ehdr32.e_shentsize;
        }

        if (sh_size < 0) {
            if (verbose) {
                fprintf(stderr, "%s: Incorrect e_shentsize\n", name);
            }

            if (brute) {
                goto dynamic_sections_traversal;
            }

            goto exit;
        }

        if (arch64) {
            if (lseek(fd, sh_offset.off64, SEEK_SET) == -1) {
                fprintf(stderr, "%s: Cannot set offset\n", name);
                goto exit;
            }
        } else {
            if (lseek(fd, sh_offset.off32, SEEK_SET) == -1) {
                fprintf(stderr, "%s: Cannot set offset\n", name);
                goto exit;
            }
        }
        

        shdr = (ElfN_Shdr*) safe_calloc(1, sh_size);

        for (int i = 0; i < sh_num; ++i) {
            if (read(fd, shdr, sh_size) != sh_size) {
                fprintf(stderr, "%s: Cannot read the Shdr\n", name);
                goto exit;
            }

            if (arch64 && shdr->shdr64.sh_type == SHT_DYNAMIC || !arch64 && shdr->shdr32.sh_type == SHT_DYNAMIC) {
                if ( \
                    arch64 && (shdr->shdr64.sh_offset < sizeof(Elf64_Ehdr) || shdr->shdr64.sh_offset >= size) || \
                    !arch64 && (shdr->shdr32.sh_offset < sizeof(Elf32_Ehdr) || shdr->shdr32.sh_offset >= size)
                ) {
                    fprintf(stderr, "%s: Incorrect offset for dynamic segment\n", name);
                    goto exit;
                }

                if (dyn_offest_arr == NULL) {
                    if (arch64) {
                        dyn_offest_arr = (ElfN_Off*) safe_calloc(1, sizeof(Elf64_Off));
                    } else {
                        dyn_offest_arr = (ElfN_Off*) safe_calloc(1, sizeof(Elf32_Off));
                    }

                    ++dyn_arr_size;
                } else {
                    repeat = false;

                    for (int j = 0; j < dyn_arr_size; ++j) {
                        if ( \
                            arch64 && shdr->shdr64.sh_offset == dyn_offest_arr[j].off64 || \
                            !arch64 && shdr->shdr32.sh_offset == dyn_offest_arr[j].off32 \
                        ) {
                            repeat = true;
                            break;
                        }
                    }

                    if (repeat) {
                        continue;
                    }

                    ++dyn_arr_size;

                    if (arch64) {
                        dyn_offest_arr = (ElfN_Off*) safe_realloc(dyn_offest_arr, sizeof(Elf64_Off) * dyn_arr_size);
                    } else {
                        dyn_offest_arr = (ElfN_Off*) safe_realloc(dyn_offest_arr, sizeof(Elf32_Off) * dyn_arr_size);
                    }                    
                }

                if (arch64) {
                    dyn_offest_arr[dyn_arr_size - 1].off64 = shdr->shdr64.sh_offset;
                } else {
                    dyn_offest_arr[dyn_arr_size - 1].off32 = shdr->shdr32.sh_offset;
                }
            }
        }

        if (dyn_arr_size > 0) {
            if (arch64) {
                dyn = (ElfN_Dyn*) safe_calloc(1, sizeof(Elf64_Dyn));
            } else {
                dyn = (ElfN_Dyn*) safe_calloc(1, sizeof(Elf32_Dyn));
            }            
        }
        
        dynamic_sections_traversal:

        if (dyn != NULL) {
            for (int i = 0; i < dyn_arr_size; ++i) {
                if (arch64) {
                    if (lseek(fd, dyn_offest_arr[i].off64, SEEK_SET) == -1) {
                        fprintf(stderr, "%s: Cannot set offset\n", name);
                        goto exit;
                    }
                } else {
                    if (lseek(fd, dyn_offest_arr[i].off32, SEEK_SET) == -1) {
                        fprintf(stderr, "%s: Cannot set offset\n", name);
                        goto exit;
                    }
                }

                if (arch64) {
                    if (read(fd, dyn, sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
                        fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                        goto exit;
                    }
                } else {
                    if (read(fd, dyn, sizeof(Elf32_Dyn)) != sizeof(Elf32_Dyn)) {
                        fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                        goto exit;
                    }
                }

                if ( \
                    arch64 && (dyn->dyn64.d_tag >= 0 && dyn->dyn64.d_tag <= 35 || \
                               dyn->dyn64.d_tag == 0x6000000d || \
                               dyn->dyn64.d_tag == 0x6ffff000 || \
                               dyn->dyn64.d_tag == 0x70000000 || \
                               dyn->dyn64.d_tag == 0x7fffffff || \
                               dyn->dyn64.d_tag == DT_MIPS_NUM) || \
                    !arch64 && (dyn->dyn32.d_tag >= 0 && dyn->dyn32.d_tag <= 35 || \
                                dyn->dyn32.d_tag == 0x6000000d || \
                                dyn->dyn32.d_tag == 0x6ffff000 || \
                                dyn->dyn32.d_tag == 0x70000000 || \
                                dyn->dyn32.d_tag == 0x7fffffff || \
                                dyn->dyn32.d_tag == DT_MIPS_NUM) \
                ) {
                    if (arch64) {
                        flag = dyn->dyn64.d_tag != DT_NULL;
                    } else {
                        flag = dyn->dyn32.d_tag != DT_NULL;
                    }

                    while (flag) {
                        if (arch64 && dyn->dyn64.d_tag == DT_STRTAB || !arch64 && dyn->dyn32.d_tag == DT_STRTAB) {
                            if (arch64) {
                                dyn_str_offset.word64 = dyn->dyn64.d_un.d_val;
                            } else {
                                dyn_str_offset.word32 = dyn->dyn32.d_un.d_val;
                            }

                            break;
                        }

                        if (arch64) {
                            if (read(fd, dyn, sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
                                if (verbose) {
                                    fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                                }
    
                                goto exit;
                            }
                        } else {
                            if (read(fd, dyn, sizeof(Elf32_Dyn)) != sizeof(Elf32_Dyn)) {
                                if (verbose) {
                                    fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                                }
    
                                goto exit;
                            }
                        }

                        if (arch64) {
                            flag = dyn->dyn64.d_tag != DT_NULL;
                        } else {
                            flag = dyn->dyn32.d_tag != DT_NULL;
                        }
                    }

                    if (arch64) {
                        if (dyn_str_offset.word64 == 0) {
                            if (verbose) {
                                fprintf(stderr, "%s: No string table for .dynamic\n", name);
                            }
    
                            goto exit;
                        }
                    } else {
                        if (dyn_str_offset.word32 == 0) {
                            if (verbose) {
                                fprintf(stderr, "%s: No string table for .dynamic\n", name);
                            }
    
                            goto exit;
                        }
                    }
                } else {
                    if (verbose) {
                        fprintf(stderr, "%s: Invalid d_tag\n", name);
                    }
                    
                    if (!brute) {
                        goto exit;
                    }
                }

                if (arch64) {
                    if (lseek(fd, dyn_offest_arr[i].off64, SEEK_SET) == -1) {
                        fprintf(stderr, "%s: Cannot set offset\n", name);
                        goto exit;
                    }
                } else {
                    if (lseek(fd, dyn_offest_arr[i].off32, SEEK_SET) == -1) {
                        fprintf(stderr, "%s: Cannot set offset\n", name);
                        goto exit;
                    }
                }

                if (arch64) {
                    if (read(fd, dyn, sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
                        fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                        goto exit;
                    }
                } else {
                    if (read(fd, dyn, sizeof(Elf32_Dyn)) != sizeof(Elf32_Dyn)) {
                        fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                        goto exit;
                    }
                }
                
                if (lib_name == NULL) {
                    lib_name = (char*) safe_calloc(NAME_MAX, sizeof(char));
                }

                if (arch64) {
                    flag = dyn->dyn64.d_tag != DT_NULL;
                } else {
                    flag = dyn->dyn32.d_tag != DT_NULL;
                }

                while (flag) {
                    if (arch64 && dyn->dyn64.d_tag == DT_NEEDED || !arch64 && dyn->dyn32.d_tag == DT_NEEDED) {
                        if (arch64) {
                            prev_offset.off64 = lseek(fd, 0, SEEK_CUR);
                            lib_name_offset.word64 = dyn->dyn64.d_un.d_val;
    
                            if (lseek(fd, dyn_str_offset.word64 + lib_name_offset.word64, SEEK_SET) == -1) {
                                fprintf(stderr, "%s: Cannot set offset\n", name);
                                goto exit;
                            }
                        } else {
                            prev_offset.off32 = lseek(fd, 0, SEEK_CUR);
                            lib_name_offset.word32 = dyn->dyn32.d_un.d_val;

                            if (lseek(fd, dyn_str_offset.word32 + lib_name_offset.word32, SEEK_SET) == -1) {
                                fprintf(stderr, "%s: Cannot set offset\n", name);
                                goto exit;
                            }
                        }
                        

                        char_counter = 0;

                        while (char_counter < MAX_NAME_LEN - 1) {
                            if (read(fd, lib_name + char_counter, 1) != 1) {
                                if (verbose) {
                                    fprintf(stderr, "%s: Cannot read the lib\n", name);
                                }
                                
                                goto exit;
                            }

                            if (*(lib_name + char_counter) == '\0') {
                                break;
                            }

                            ++char_counter;
                        }

                        if (list_of_libs == NULL) {
                            lib_counter = 1;
                            list_of_libs = (char**) safe_calloc(2, sizeof(char*));
                            list_of_libs[0] = (char*) safe_calloc(sizeof(int), 1);   
                        } else {
                            ++lib_counter;
                            list_of_libs = (char**) safe_realloc(list_of_libs, sizeof(char*) * (lib_counter + 1));
                        }

                        list_of_libs[lib_counter] = (char*) safe_calloc(strnlen(lib_name, MAX_NAME_LEN - 1) + 1, 1);
                        strncpy(list_of_libs[lib_counter], lib_name,  strnlen(lib_name, MAX_NAME_LEN - 1));
                        
                        if (arch64) {
                            if (lseek(fd, prev_offset.off64, SEEK_SET) == -1) {
                                fprintf(stderr, "%s: Cannot set offset\n", name);
                                goto exit;
                            }
                        } else {
                            if (lseek(fd, prev_offset.off32, SEEK_SET) == -1) {
                                fprintf(stderr, "%s: Cannot set offset\n", name);
                                goto exit;
                            }
                        }
                    }
        
                    if (arch64) {
                        if (read(fd, dyn, sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
                            fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                            goto exit;
                        }
                    } else {
                        if (read(fd, dyn, sizeof(Elf32_Dyn)) != sizeof(Elf32_Dyn)) {
                            fprintf(stderr, "%s: Cannot read the ElfN_Dyn\n", name);
                            goto exit;
                        }
                    }

                    if (arch64) {
                        flag = dyn->dyn64.d_tag != DT_NULL;
                    } else {
                        flag = dyn->dyn32.d_tag != DT_NULL;
                    }
                }                
            }
            if (list_of_libs != NULL) {
                memcpy(list_of_libs[0], &lib_counter, sizeof(int));                 
            }
            
            done = true;
        }
    }

    exit:

    if (close(fd) == -1 && fd != -1) {
        fprintf(stderr, "%s: Cannot close file safely! Possible data corruption!\n", name);
    }

    elf_header = safe_free(elf_header);
    phdr = safe_free(phdr);
    dyn = safe_free(dyn);
    shdr = safe_free(shdr);
    lib_name = safe_free(lib_name);
    dyn_offest_arr = safe_free(dyn_offest_arr);

    if (!done) {
        if (list_of_libs != NULL) {           
            for (int i = 1; i <=  (int) list_of_libs[0][0]; ++i) {
                list_of_libs[i] = safe_free(list_of_libs[i]);
            }

            list_of_libs[0] = safe_free(list_of_libs[0]);
            list_of_libs = safe_free(list_of_libs);
        }
    }

    return list_of_libs;
}
