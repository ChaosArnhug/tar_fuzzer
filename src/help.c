#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "help.h"
#include "statstable.h"

void init_stats_counter(stats_counter_t* stats_counter)
{
    memset(stats_counter, 0, sizeof(stats_counter_t));
}

unsigned int calculate_checksum(tar_t* header)
{
    memset(header->chksum, ' ', LENGTH_CHKSUM);

    unsigned int check = 0;
    const unsigned char* raw = (unsigned char*)header;
    for (int i = 0; i < HEADER_LENGTH; i++)
    {
        check += raw[i];
    }

    snprintf(header->chksum, sizeof(header->chksum), "%06o0", check);

    header->chksum[6] = '\0';
    header->chksum[7] = ' ';
    return check;
}

int extract(const char* path_extractor, stats_counter_t* stats_counter)
{
    stats_counter->extraction_counter++;

    int rv = 0;
    char current_file[LENGTH_NAME];
    snprintf(current_file, sizeof(current_file), "temp_%d.tar",
             stats_counter->archive_created_counter);


    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s 2>/dev/null", path_extractor, current_file);

    FILE* fp = popen(cmd, "r");
    if (!fp)
    {
        return -1; /* popen() error */
    }

    char buf[128];
    if (fgets(buf, sizeof(buf), fp) == NULL)
    {
        /* If extractor prints nothing, do not rename. */
        goto finally;
    }

    /* The string is "*** The program has crashed ***\n" */
    /* which is exactly 32 chars + a null terminator => length 33. */
    if (strncmp(buf, "*** The program has crashed ***\n", 33) == 0)
    {
        rv = 1; /* indicates a crash was found */
        stats_counter->crash_counter++;

        char success_name[LENGTH_NAME];
        snprintf(success_name, sizeof(success_name), "success_%d.tar",
                 stats_counter->crash_counter);

        if (rename(current_file, success_name) == 0)
        {
            pclose(fp);
            return 1;
        }
    }

finally:
    if (pclose(fp) == -1)
    {
        rv = -1;
    }
    return rv;
}

int handle_extraction(const char* path_extractor, int* crash_counter, stats_table_t* stats,
                       const int crash_type, const enum TarHeaderField field_type,
                       stats_counter_t* stats_counter)
{
    const int return_value = extract(path_extractor, stats_counter);
    switch (return_value)
    {
    case 0:
        /* No crash */
        update_stats(stats, 0, crash_type, field_type);
        return 0;

    case 1:
        /* The extractor printed the crash message. */
        (*crash_counter)++;
        update_stats(stats, 1, crash_type, field_type);
        return 1;

    // case 2:
    //     /* The extractor crashed, but rename() failed. */
    //     //update_stats(stats, 1, crash_type, field_type);
    //     /* If you want to do something else on rename failure, do it here. */
    //     break;

    default:
        /* popen or pclose failed => treat it as no crash. */
        update_stats(stats, 0, crash_type, field_type);
        return 0;
    }
}

void init_tar_header(tar_t* header, stats_counter_t* stat_counter)
{
    char archive_name[LENGTH_NAME];
    snprintf(archive_name, sizeof(archive_name), "temp_%d.txt",
             stat_counter->archive_created_counter++);

    char linkname[LENGTH_LINKNAME];
    memset(linkname, '0', LENGTH_LINKNAME - 1);
    linkname[LENGTH_LINKNAME - 1] = '\0'; // Null-terminate

    char size[LENGTH_SIZE];
    memset(size, '0', LENGTH_SIZE - 1);
    size[LENGTH_SIZE - 1] = '\0'; // Null-terminate

    // Initialize with designated initializers
    *header = (tar_t){
        .name = {0},
        .mode = DEFAULT_MODE_FIELD,
        .uid = DEFAULT_UNIX_USER_ID,
        .gid = DEFAULT_UNIX_GROUP_ID,
        .size = {0},
        .mtime = {0},
        .chksum = {0},
        .typeflag = REGTYPE,
        .linkname = {0},
        .magic = TMAGIC,
        .version = TVERSION,
        .uname = DEFAULT_UNIX_USER,
        .gname = DEFAULT_UNIX_USER,
        .devmajor = DEFAULT_UNIX_USER_ID,
        .devminor = DEFAULT_UNIX_USER_ID,
        .prefix = {0},
        .padding = {0}
    };


    strncpy(header->name, archive_name, sizeof(header->name) - 1);
    header->name[LENGTH_NAME - 1] = '\0'; // Force null termination

    snprintf(header->size, sizeof(header->size), "%s", size);
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", time(NULL));
    snprintf(header->linkname, sizeof(header->linkname), "%s", linkname);
    calculate_checksum(header);
}

void create_tar(tar_t* header, const char* content_header, const size_t content_header_size,
                const char* end_data, const size_t end_size, const stats_counter_t* stats_counter)
{
    calculate_checksum(header);
    char filename[LENGTH_NAME];
    snprintf(filename, sizeof(filename), "temp_%d.tar",
             stats_counter->archive_created_counter);

    FILE* fp = fopen(filename, "wb");
    if (fp == NULL)
    {
        // Error handling or exit
        return;
    }

    if (fwrite(header, sizeof(tar_t), 1, fp) != 1)
    {
        fclose(fp);
        return;
    }
    if (content_header_size > 0 &&
        fwrite(content_header, content_header_size, 1, fp) != 1)
    {
        fclose(fp);
        return;
    }
    if (end_size > 0 && fwrite(end_data, end_size, 1, fp) != 1)
    {
        fclose(fp);
        return;
    }
    fclose(fp);
}

void create_empty_tar(tar_t* header, const stats_counter_t* stats_counter)
{
    const char end_data[END_BYTES] = {0};
    create_tar(header, NULL, 0, end_data, END_BYTES, stats_counter);
}

void remove_tar_archives()
{
    // Base command to remove unwanted non-tar files
    char command[2048] = "find . -type f";

    // Exclude keep_files
    for (size_t i = 0; i < sizeof(keep_files) / sizeof(keep_files[0]); i++)
    {
        snprintf(command + strlen(command), sizeof(command) - strlen(command),
                 " ! -name '%s'", keep_files[i]);
    }

    // Exclude paths from deletion
    for (size_t i = 0; i < sizeof(exclude_paths) / sizeof(exclude_paths[0]); i++)
    {
        snprintf(command + strlen(command), sizeof(command) - strlen(command),
                 " ! -path '%s'", exclude_paths[i]);
    }

    // Only remove files that are not .tar
    snprintf(command + strlen(command), sizeof(command) - strlen(command),
             " -delete");

    system(command);

    const char tar_removal_command[512] = "find . -name 'temp_*.tar' -exec rm -rf {} +";
    system(tar_removal_command);

    system("find . -type l -name 'temp_*' -delete");

    // For directories
    system("find . -type d -name 'temp_*' -exec rm -rf {} \\; 2>/dev/null");

    // For FIFOs (named pipes)
    system("find . -type p -name 'temp_*' -delete");
}


void clear_terminal()
{
    system("clear");
}



void init_tar_header_with_content(tar_t* header, stats_counter_t* stat_counter, char* content)
{
    char archive_name[LENGTH_NAME];
    snprintf(archive_name, sizeof(archive_name), "temp_%d.txt",
             stat_counter->archive_created_counter++);

    char linkname[LENGTH_LINKNAME];
    memset(linkname, '0', LENGTH_LINKNAME - 1);
    linkname[LENGTH_LINKNAME - 1] = '\0'; // Null-terminate

    // Initialize with designated initializers
    *header = (tar_t){
        .name = {0},
        .mode = DEFAULT_MODE_FIELD,
        .uid = DEFAULT_UNIX_USER_ID,
        .gid = DEFAULT_UNIX_GROUP_ID,
        .size = {0},
        .mtime = {0},
        .chksum = {0},
        .typeflag = REGTYPE,
        .linkname = {0},
        .magic = TMAGIC,
        .version = TVERSION,
        .uname = DEFAULT_UNIX_USER,
        .gname = DEFAULT_UNIX_USER,
        .devmajor = DEFAULT_UNIX_USER_ID,
        .devminor = DEFAULT_UNIX_USER_ID,
        .prefix = {0},
        .padding = {0}
    };


    strncpy(header->name, archive_name, sizeof(header->name) - 1);
    header->name[LENGTH_NAME - 1] = '\0'; // Force null termination

    snprintf(header->size, sizeof(header->size), "%011o", (unsigned int)strlen(content));
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", time(NULL));
    snprintf(header->linkname, sizeof(header->linkname), "%s", linkname);
    calculate_checksum(header);
}

int tar_archive_mul_file(const char* tar_filename, file_to_archive* files, size_t file_count) {
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
        if (fwrite(file->header, sizeof(tar_t), 1, tar_file) != 1) {
            perror("Error create_tar_archive: failed to write header to tar file\n");
            continue;
        }

        // Write file content
        size_t bytes_written = 0;
        while (file->content != NULL && bytes_written < file->content_size) {
            size_t chunk_size = (file->content_size - bytes_written) > LENGTH_TAR_BLOCK ? LENGTH_TAR_BLOCK : (file->content_size - bytes_written);
            if (fwrite(file->content + bytes_written, sizeof(char), chunk_size, tar_file) != chunk_size) {
                perror("Error create_tar_archive: failed to write content to tar file\n");
                break;
            }
            bytes_written += chunk_size;
        }

        // File last chunk if less than 512 bytes
        size_t padding_size = (file->content_size % LENGTH_TAR_BLOCK == 0) ? 0 : (LENGTH_TAR_BLOCK - (file->content_size % LENGTH_TAR_BLOCK));
        if (padding_size != LENGTH_TAR_BLOCK) {
            char padding[LENGTH_TAR_BLOCK] = {0};
            if (fwrite(padding, 1, padding_size, tar_file) != padding_size) {
                perror("Error create_tar_archive: failed to write padding to tar file\n");
                fclose(tar_file);
                return -1;
            }
        }
    }

    // Archive should end with two empty blocks as explained in https://www.gnu.org/software/tar/manual/html_node/Standard.html
    char end_of_archive[END_BYTES] = {0};
    if (fwrite(end_of_archive, sizeof(char), END_BYTES, tar_file) != END_BYTES) {
        perror("Error create_tar_archive: failed to write end of archive to tar file\n");
        fclose(tar_file);
        return -1;
    }

    fclose(tar_file);
    return 0;
}
