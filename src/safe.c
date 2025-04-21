#include <stdio.h>
#include <stdlib.h>


void* safe_calloc(size_t nmemb, size_t size) {
    void* ret = calloc(nmemb, size);

    if (ret == NULL) {
        perror("Cannot allocate memory!");
        exit(1);
    }

    return ret;
}


void* safe_realloc(void *ptr, size_t size) {
    void* ret = realloc(ptr, size);

    if (ret == NULL) {
        perror("Cannot reallocate memory!");
        exit(1);
    }

    return ret;
}


void* safe_free(void *ptr) {
    free(ptr);
    return NULL;
}
