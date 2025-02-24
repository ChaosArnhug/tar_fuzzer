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

    /* We'll read up to one line of output from the extractor. */
    char buf[128];
    if (fgets(buf, sizeof(buf), fp) == NULL)
    {
        /* If extractor prints nothing, do not rename. */
        goto finally;
    }

    /* Compare with your known crash marker. */
    /* The string in your code was "*** The program has crashed ***\n" */
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

void handle_extraction(const char* path_extractor, int* crash_counter, stats_table_t* stats,
                       const int crash_type, const enum TarHeaderField field_type,
                       stats_counter_t* stats_counter, char* current_status)
{
    const int return_value = extract(path_extractor, stats_counter);
    //printf("Value: %d\n", return_value);
    switch (return_value)
    {
    case 0:
        /* No crash */
        update_stats(stats, 0, crash_type, field_type);
        break;

    case 1:
        /* The extractor printed the crash message. */
        (*crash_counter)++;
        update_stats(stats, 1, crash_type, field_type);
        break;

    // case 2:
    //     /* The extractor crashed, but rename() failed. */
    //     //update_stats(stats, 1, crash_type, field_type);
    //     /* If you want to do something else on rename failure, do it here. */
    //     break;

    default:
        /* popen or pclose failed => treat it as no crash. */
        update_stats(stats, 0, crash_type, field_type);
        break;
    }
}

void init_tar_header(tar_t* header, stats_counter_t* stat_counter)
{
    char archive_name[LENGTH_NAME];
    snprintf(archive_name, sizeof(archive_name), "temp_%d.tar",
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


    snprintf(header->name, sizeof(header->name) - 1, "%s", archive_name);
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
}


void clear_terminal()
{
    system("clear");
}
