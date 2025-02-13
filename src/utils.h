#include "tar.h"

typedef struct file_to_archive {
    posix_header* header;
    char* content;
    size_t content_size;
} file_to_archive;

unsigned int calculate_checksum(posix_header* entry);
void init_posix_header(posix_header* header, const char* filename, size_t file_size);
void init_file_to_archive(file_to_archive* file, posix_header* header, char* content, size_t content_size);
int create_tar_archive(const char* tar_filename, file_to_archive* files, size_t file_count);
int extractor(char* executable, char* archive);