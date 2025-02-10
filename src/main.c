#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

void test_empty_field(tar_t* header, char* field, size_t size) {
    default_tar_header(header);

    char* archive_path = header->name;
    strncpy(field, "", size);
    create_tar_archive(header);
    if (extract("./archive0.tar") == 1) {
        printf("Crash detected with empty field of size %zu\n", size);
    }
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: ./tar_fuzzer <path_to_tar_extractor>\n");
        return 1;
    }

    printf("*** Lunching the tar fuzzer with %s as tar extractor ***\n", argv[1]);

    tar_t header;
    test_empty_field(&header, header.name, 100);

    printf("*** The tar fuzzer has finished ***\n");
    return 0;
}