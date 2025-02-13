#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tar.h"
#include "utils.h"

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

void init_file_to_archive(file_to_archive* file, posix_header* header, char* content, size_t content_size) {
    if (header == NULL) {
        perror("Error init_file_to_archive: header is NULL\n");
        return;
    }

    if (content != NULL && content_size <= 0) {
        perror("Error init_file_to_archive: content is not NULL so content_size cannot be less or equal to 0\n");
        return;
    }
    
    file->header = header;
    file->content = content;
    file->content_size = content_size;
    return;
}
// Easier to give the content directly. Other solution is to create a file with the content and give the file path
/** Create a tar archive
    tar_filename: the name of the tar file to create (ex: test.rar)
    content_to_archive: the content to archive in the tar file
    content_size: the size of the content to archive == strlen(content_to_archive) in normal case
    header_content_to_archive: the header of the content to archive (! do not forget to update the header if you want something else than the default values)
*/
int create_tar_archive(const char* tar_filename, file_to_archive* files, size_t file_count) {
    if (tar_filename == NULL || files == NULL) {
        perror("Error create_tar_archive: tar_filename or files is NULL\n");
        return -1;
    }

    FILE *tar_file;
    if (!(tar_file = fopen(tar_filename, "wb"))) {
        perror("Error create_tar_archive: Cannot open file\n");
        return -1;
    }

    for (size_t i = 0; i < file_count; i++) {
        file_to_archive* file = &files[i];

        if (file->header == NULL) {
            perror("Error create_tar_archive: file header is NULL\n");
            continue;
        }

        if (file->content != NULL && file->content_size <= 0) {
            perror("Error create_tar_archive: content is not NULL so content_size cannot be less or equal to 0\n");
            continue;
        }

        // Write header in the tar file
        if (fwrite(file->header, sizeof(posix_header), 1, tar_file) != 1) {
            perror("Error create_tar_archive: failed to write header to tar file\n");
            continue;
        }

        // Write file content
        size_t bytes_written = 0;
        while (file->content != NULL && bytes_written < file->content_size) {
            size_t chunk_size = (file->content_size - bytes_written) > TAR_BLOCK_SIZE ? TAR_BLOCK_SIZE : (file->content_size - bytes_written);
            if (fwrite(file->content + bytes_written, sizeof(char), chunk_size, tar_file) != chunk_size) {
                perror("Error create_tar_archive: failed to write content to tar file\n");
                break;
            }
            bytes_written += chunk_size;
        }

        // File last chunk if less than 512 bytes
        size_t padding_size = TAR_BLOCK_SIZE - (file->content_size % TAR_BLOCK_SIZE); // Size missing to complete a 512 block with last block of content
        if (padding_size != TAR_BLOCK_SIZE) {
            char padding[TAR_BLOCK_SIZE] = {0};
            if (fwrite(padding, 1, padding_size, tar_file) != padding_size) {
                perror("Error create_tar_archive: failed to write padding to tar file\n");
                fclose(tar_file);
                return -1;
            }
        }
    }

    // Archive should end with two empty blocks as explained in https://www.gnu.org/software/tar/manual/html_node/Standard.html
    char end_of_archive[TAR_BLOCK_SIZE * 2] = {0};
    if (fwrite(end_of_archive, sizeof(char), TAR_BLOCK_SIZE * 2, tar_file) != TAR_BLOCK_SIZE * 2) {
        perror("Error create_tar_archive: failed to write end of archive to tar file\n");
        fclose(tar_file);
        return -1;
    }

    fclose(tar_file);
    return 0;
}

// BETA TEST : executable and archive path are limited in size because of how cmd variable works
/**
 * Launches another executable given as argument (MODIFIED TEACHER FUNCTION),
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int extractor(char* executable, char* archive) {
    if (executable == NULL || archive == NULL) {
        perror("Error extractor: executable or archive is NULL\n");
        return -1;
    }
    // Maybe check if path are correct ? But dunno since it's done in main

    int rv = 0;
    char cmd[51];
    strncpy(cmd, executable, 25);
    cmd[26] = '\0';
    strncat(cmd, archive, 25);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

int remove_file (char* filename) {
    if (filename == NULL) {
        perror("Error remove_file: filename is NULL\n");
        return -1;
    }

    if (remove(filename) != 0) {
        perror("Error remove_file: Cannot remove file\n");
        return -1;
    }
    return 0;
}