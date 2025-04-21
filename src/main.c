#include <fcntl.h>
#include <getopt.h>
#include <dirent.h>
#include <linux/limits.h>
#include <stdio.h>
#include "bldd.c"


#if defined(__x86_64__)
    #define ARCH_NAME " x86_64 "
#elif defined(__aarch64__)
    #define ARCH_NAME " aarch64 "
#elif defined(__i386__)
    #define ARCH_NAME " i386 (x86) "
#elif defined(__arm__)
    #define ARCH_NAME " armv7 "
#else
    #error "Unsupported architecture"
#endif


void* safe_calloc(size_t nmemb, size_t size); /* safe.c */
void* safe_realloc(void *ptr, size_t size); /* safe.c */
void* safe_free(void *ptr); /* safe.c */
char** bdll(char* name, bool verbose, bool brute); /* bdll.c */


typedef struct {
    char* lib;
    char** files;
    int counter;
} Lib;


typedef struct {
    Lib** libs;
    int counter;
} Lib_List;


void* safe_free_lib(Lib* lib) {
    if (lib == NULL) {
        return NULL;
    }

    lib->lib = safe_free(lib->lib);

    for (int i = 0; i < lib->counter; ++i) {
        lib->files[i] = NULL;
    }

    lib->files = safe_free(lib->files);
    lib = safe_free(lib);
    return NULL;
}


void* safe_free_lib_list(Lib_List* lib_list) {
    if (lib_list == NULL) {
        return NULL;
    }

    for (int i = 0; i < lib_list->counter; ++i) {
        lib_list->libs[i] = safe_free_lib(lib_list->libs[i]);
    }

    lib_list->libs = safe_free(lib_list->libs);
    lib_list = safe_free(lib_list);
    return NULL;
}


int compare_libs(const void *a, const void *b) {
    const Lib *lib1 = *(const Lib**)a;
    const Lib *lib2 = *(const Lib**)b;
    
    if (lib1->counter > lib2->counter) {
        return -1;
    }

    if (lib1->counter < lib2->counter) {
        return 1;
    }
    
    return 0;
}


void write_report(FILE* stream, Lib_List* lib_list, char* dirname) {
    fprintf(stream, "Report on dynamic used libraries by ELF executables on %s\n\n\n", dirname);
    fprintf(stream, "---------- %s ----------\n\n", ARCH_NAME);

    if (lib_list != NULL) {
        for (int i = 0; i < lib_list->counter; ++i) {
            fprintf(stream, "\n%s (%d execs)\n", lib_list->libs[i]->lib, lib_list->libs[i]->counter);

            for (int j = 0; j < lib_list->libs[i]->counter; ++j) {
                fprintf(stream, "\t\t-> %s\n", lib_list->libs[i]->files[j]);
            }
        }
    }
}


void usage() {
    puts("Usage: bldd [OPTIONS]...\n"
        "\t-h, --help          print this help and exit\n"
        "\t-d, --directory     specify directory to check all files inside\n"
        "\t-v, --verbose       activate verbose mode\n"
        "\t-b, --brute         activate brute force mode (it will try to explore corrupted files, but may crash! BE CAREFUL!!!)\n"
        "\t-o, --output        specify file for report generation\n");
    return;
}


int main(int argc, char** argv) {
    char** files = NULL;
    char* name = NULL;
    char* dirname = NULL;
    char* output_file = NULL;
    struct dirent* entry = NULL;
    DIR* work_dir = NULL;
    FILE* stream = NULL;
    Lib_List* lib_list = NULL;
    int counter = 0;
    int files_num = 0;
    int opt = 0;
    bool help = false;
    bool dir = false;
    bool verbose = false;
    bool brute = false;
    bool out = false;
    bool found = false;

    struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"directory", required_argument, 0, 'd'},
        {"verbose",   no_argument,       0, 'v'},
        {"brute",     no_argument,       0, 'b'},
        {"output",    required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
    } else {
        while ((opt = getopt_long(argc, argv, "hd:vbo:", long_options, NULL)) != -1) {
            switch (opt) {
                case 'h':
                    usage();
                    goto exit;
                case 'd':
                    if (dir) {
                        usage();
                        goto exit;
                    }

                    dir = true;
                    dirname = (char*) safe_calloc(strnlen(optarg, NAME_MAX) + 1, 1);
                    strncpy(dirname, optarg, strnlen(optarg, NAME_MAX));
                    break;
                case 'v':
                    if (verbose) {
                        usage();
                        goto exit;
                    }

                    verbose = true;
                    break;
                case 'b':
                    if (brute) {
                        usage();
                        goto exit;
                    }

                    brute = true;
                    break;
                case 'o':
                    if (out) {
                        usage();
                        goto exit;
                    }

                    out = true;
                    output_file = (char*) safe_calloc(strnlen(optarg, NAME_MAX) + 1, 1);
                    strncpy(output_file, optarg, strnlen(optarg, NAME_MAX));
                    break;
                case '?':
                    usage();
                    return EXIT_FAILURE;
                default:
                    usage();
                    return EXIT_FAILURE;
            }
        }
    }

    if (!dir) {
        dirname = (char*) safe_calloc(2, 1);
        dirname[0] = '.';
    }

    work_dir = opendir(dirname);

    if (work_dir == NULL) {
        fprintf(stderr, "Cannot open directory: %s\n", dirname);
        goto exit;
    }

    name = (char*) safe_calloc(NAME_MAX + 1, 1);
    strncpy(name, dirname, strnlen(dirname, NAME_MAX));
    name[strnlen(name, NAME_MAX)] = '/';

    while (true) {
        entry = readdir(work_dir);

        if (entry == NULL) {
            break;
        }

        strncat(name, entry->d_name, strnlen(entry->d_name, NAME_MAX));
        char** list = bdll(name, verbose, brute);

        if (list != NULL) {
            if (files == NULL) {
                files_num = 1;
                files = (char**) safe_calloc(1, sizeof(char*));
                files[0] = (char*) safe_calloc(strnlen(name, NAME_MAX) + 1, 1);
                strncpy(files[0], name, strnlen(name, NAME_MAX));
            } else {
                ++files_num;
                files = (char**) safe_realloc(files, sizeof(char*) * files_num);
                files[files_num - 1] = (char*) safe_calloc(strnlen(name, NAME_MAX) + 1, 1);
                strncpy(files[files_num - 1], name, strnlen(name, NAME_MAX));
            }

            memcpy(&counter, list[0], sizeof(int)); 
            
            for (int i = 1; i <= counter; ++i) {
                found = false;

                if (lib_list == NULL) {
                    lib_list = (Lib_List*) safe_calloc(1, sizeof(Lib_List));
                    lib_list->libs = (Lib**) safe_calloc(1, sizeof(Lib*));
                    lib_list->libs[0] = (Lib*) safe_calloc(1, sizeof(Lib));
                    lib_list->libs[0]->files = (char**) safe_calloc(1, sizeof(char*));
                    lib_list->libs[0]->files[0] = files[files_num - 1];
                    lib_list->libs[0]->lib = list[i];
                    lib_list->libs[0]->counter = 1;
                    lib_list->counter = 1;
                } else {
                    for (int j = 0; j < lib_list->counter; ++j) {
                        if (strnlen(lib_list->libs[j]->lib, MAX_NAME_LEN) == strnlen(list[i], MAX_NAME_LEN) && !strncmp(lib_list->libs[j]->lib, list[i], strnlen(list[i], MAX_NAME_LEN))) {
                            ++lib_list->libs[j]->counter;
                            lib_list->libs[j]->files = (char**) safe_realloc(lib_list->libs[j]->files, sizeof(char*) * lib_list->libs[j]->counter);
                            lib_list->libs[j]->files[lib_list->libs[j]->counter - 1] = files[files_num - 1];
                            found = true;
                            list[i] = safe_free(list[i]);
                            break;
                        }                        
                    }

                    if (found) {
                        continue;
                    }

                    ++lib_list->counter;
                    lib_list->libs = (Lib**) safe_realloc(lib_list->libs, sizeof(Lib*) * lib_list->counter);
                    lib_list->libs[lib_list->counter - 1] = (Lib*) safe_calloc(1, sizeof(Lib));
                    lib_list->libs[lib_list->counter - 1]->files = (char**) safe_calloc(1, sizeof(char*));
                    lib_list->libs[lib_list->counter - 1]->files[0] = files[files_num - 1];
                    lib_list->libs[lib_list->counter - 1]->lib = list[i];
                    lib_list->libs[lib_list->counter - 1]->counter = 1;
                }
            }

            list[0] = safe_free(list[0]);
            list = safe_free(list);
        }
        memset(name + strnlen(dirname, NAME_MAX) + 1, 0, strnlen(entry->d_name, NAME_MAX));
    }

    if (closedir(work_dir) == -1) {
        fprintf(stderr, "Eerror when closing %s", dirname);
    }

    if (out) {
        stream = fopen(output_file, "w");
    } else {
        stream = stdout;
    }
        
    if (stream == NULL) {
        if (verbose) {
            fprintf(stderr, "%s: Cannot open the file\n", output_file);
        }

        goto exit;
    }

    if (lib_list != NULL) {
        qsort(lib_list->libs, lib_list->counter, sizeof(Lib*), compare_libs);
    }

    write_report(stream, lib_list, dirname);

    if (out) {
        if (fclose(stream) == EOF) {
            fprintf(stderr, "%s: Cannot close file safely! Possible data corruption!\n", name);
        }
    }
    
    exit:

    for (int i = 0; i < files_num; ++i) {
        files[i] = safe_free(files[i]);
    }
    
    files = safe_free(files);
    lib_list = safe_free_lib_list(lib_list);
    name = safe_free(name);
    dirname = safe_free(dirname);
    output_file = safe_free(output_file);
    return 0;
}
