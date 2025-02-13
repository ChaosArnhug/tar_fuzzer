#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tar.h"

/**
 * Computes the checksum for a tar header and encode it on the header (Teacher function)
 * @param entry: The tar header
 * @return the value of the checksum
 */
 unsigned int calculate_checksum(posix_header* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

void init_posix_header(posix_header* header, const char* filename, size_t file_size) {

    if (header == NULL || filename == NULL) {
        perror("Error init_posix_header: header or filename is NULL\n");
        return;
    }
    memset(header, 0, sizeof(struct posix_header));

    strncpy(header->name, filename, 100); 
    strncpy(header->mode, "0000644", 8);
    strncpy(header->uid, "0000000", 8);
    strncpy(header->gid, "0000000", 8);
    snprintf(header->size, sizeof(header->size), "%011o", (unsigned int)file_size);
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", time(NULL));
    header->typeflag = REGTYPE;
    strncpy(header->linkname, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 100);
    strncpy(header->magic, TMAGIC, TMAGLEN);
    strncpy(header->version, TVERSION, TVERSLEN);
    strncpy(header->uname, "default_user", 32);
    strncpy(header->gname, "default_group", 32);
    // Not sure how we should handle these + padding and size
    strncpy(header->devmajor, "0000000", 8);
    strncpy(header->devminor, "0000000", 8);

    // Could be removed if logic change (+ must be at the end here because checksum of current header content) 
    calculate_checksum(header);
}

// Easier to give the content directly. Other solution is to create a file with the content and give the file path
/** Create a tar archive
    tar_filename: the name of the tar file to create (ex: test.rar)
    content_to_archive: the content to archive in the tar file
    content_size: the size of the content to archive == strlen(content_to_archive) in normal case
    header_content_to_archive: the header of the content to archive (! do not forget to update the header if you want something else than the default values)
*/
int create_tar_archive(const char* tar_filename, const char* content_to_archive, size_t content_size, posix_header* header_content_to_archive) {
    if (tar_filename == NULL || header_content_to_archive == NULL) {
        perror("Error add_file_to_tar: tar_filename or header_content_to_archive is NULL\n");
        return -1;
    }

    if (content_to_archive != NULL && content_size <= 0) {
        perror("Error add_file_to_tar: content_to_archive is not NULL so content_size cannot be less or eqaul to 0\n");
        return -1;
    }

    FILE *tar_file;
    if (!(tar_file = fopen(tar_filename, "wb"))) {
        perror("Error create_tar_archive: Cannot open file %s\n");
        return -1;
    }

    //Write header in the tar file
    if (fwrite(header_content_to_archive, sizeof(posix_header), 1, tar_file) != 1){
        perror("Error add_file_to_tar: failed to  write header to tar file");
        fclose(tar_file);
        return -1;
    };

    // Write file content 
    size_t bytes_written = 0;
    while(content_to_archive != NULL && bytes_written < content_size) {
        size_t chunk_size = (content_size - bytes_written) > TAR_BLOCK_SIZE ? TAR_BLOCK_SIZE : (content_size - bytes_written);
        if (fwrite(content_to_archive + bytes_written, sizeof(char), chunk_size, tar_file) != chunk_size) {
            perror("Error add_file_to_tar: failed to write content to tar file");
            fclose(tar_file);
            return -1;
        }
        bytes_written += chunk_size;
    }

    //File last chunk if less than 512 bytes
    size_t padding_size = TAR_BLOCK_SIZE - (content_size % TAR_BLOCK_SIZE); // Size missing to complete a 512 bloc with last bloc of content
    if (padding_size != TAR_BLOCK_SIZE) {
        char padding[TAR_BLOCK_SIZE] = {0};
        if (fwrite(padding, 1, padding_size, tar_file) != padding_size) {
            perror("Error add_file_to_tar: failed to write padding to tar file");
            fclose(tar_file);
            return -1;
        }
    }

    // Archive should end with two empty blocks as explained in https://www.gnu.org/software/tar/manual/html_node/Standard.html
    char end_of_archive[TAR_BLOCK_SIZE * 2] = {0};
    if (fwrite(end_of_archive, sizeof(char), TAR_BLOCK_SIZE * 2, tar_file) != TAR_BLOCK_SIZE * 2) {
        perror("Error add_file_to_tar: failed to write end of archive to tar file");
        fclose(tar_file);
        return -1;

    };

    fclose(tar_file);
    return 0;
}