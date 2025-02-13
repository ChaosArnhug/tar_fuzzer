#include "tar.h"

unsigned int calculate_checksum(posix_header* entry);
void init_posix_header(posix_header* header, const char* filename, size_t file_size);
int create_tar_archive(const char* tar_filename, const char* content_to_archive, size_t content_size, posix_header* header_content_to_archive);