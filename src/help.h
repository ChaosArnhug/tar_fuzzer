#ifndef HELP_H
#define HELP_H

#include "constants.h"
#include "statstable.h"

typedef struct tar_t
{
    /* byte offset */
    char name[LENGTH_NAME]; /*   0 */
    char mode[LENGTH_MODE]; /* 100 */
    char uid[LENGTH_UID]; /* 108 */
    char gid[LENGTH_GID]; /* 116 */
    char size[LENGTH_SIZE]; /* 124 */
    char mtime[LENGTH_MTIME]; /* 136 */
    char chksum[LENGTH_CHKSUM]; /* 148 */
    char typeflag; /* 156 */
    char linkname[LENGTH_LINKNAME]; /* 157 */
    char magic[LENGTH_MAGIC]; /* 257 */
    char version[LENGTH_VERSION]; /* 263 */
    char uname[LENGTH_UNAME]; /* 265 */
    char gname[LENGTH_GNAME]; /* 297 */
    char devmajor[LENGTH_DEVMAJOR]; /* 329 */
    char devminor[LENGTH_DEVMINOR]; /* 337 */
    char prefix[LENGTH_PREFIX]; /* 345 */
    char padding[LENGTH_PADDING]; /* 500 */
} tar_t;

typedef struct file_to_archive {
    tar_t* header;
    char* content;
    size_t content_size;
} file_to_archive;

typedef struct stats_counter_t
{
    int extraction_counter;
    int crash_counter;
    int archive_created_counter;

    int name_field_vulnerabilities_counter;
    int mode_field_vulnerabilities_counter;
    int uid_field_vulnerabilities_counter;
    int gid_field_vulnerabilities_counter;
    int size_field_vulnerabilities_counter;
    int mtime_field_vulnerabilities_counter;
    int checksum_field_vulnerabilities_counter;
    int typeflag_field_vulnerabilities_counter;
    int linkname_field_vulnerabilities_counter;
    int magic_field_vulnerabilities_counter;
    int version_field_vulnerabilities_counter;
    int uname_field_vulnerabilities_counter;
    int gname_field_vulnerabilities_counter;
    int eof_vulnerabilities_counter;
    int crash_overflow_value_counter;
    int crash_injection_attack_counter;
    int crash_miscellaneous_counter;

    int crash_empty_counter;
    int crash_not_ascii_counter;
    int crash_not_integer_counter;
    int crash_negative_value_counter;
    int crash_too_short_counter;
    int crash_not_octal_counter;
    int crash_null_byte_in_the_middle_counter;
    int crash_cut_middle_counter;
    int crash_no_null_bytes_counter;
    int crash_not_ending_with_null_byte_counter;
    int crash_special_character_counter;
    int crash_mode_permission_counter;
    int crash_size_counter;
} stats_counter_t;

/*
 * Initializes the test stats counter struct with memset
 *
 * @param status_counter: the status counter to initialize
 */
void init_stats_counter(stats_counter_t* stats_counter);

/*
 * Calculates the checksum of a tar header
 *
 * @author: professor
 * @param header: the tar header to calculate the checksum for
 * @return: the calculated checksum
 */
unsigned int calculate_checksum(tar_t* header);

/*
 * Extracts a tar archive using the provided tar extractor and updates the stats counter
 *
 * @author: professor
 * @param path_extractor: the path to the tar extractor
 * @param stats_counter: the stats counter to update
 * @return: 1 if the tar extraction crashed, 0 otherwise
 */
int extract(const char* path_extractor, stats_counter_t* stats_counter);

/*
 * Creates a tar archive with the provided header and content
 *
 * @param header: the tar header to use
 * @param content_header: the content to use
 * @param content_header_size: the size of the content
 * @param end_data: the end data to use
 * @param end_size: the size of the end data
 * @param stats_counter: the stats counter to name files with %d increment
 */
void create_tar(tar_t* header, const char* content_header, size_t content_header_size, const char* end_data,
                size_t end_size, const stats_counter_t* stats_counter);
/*
 * Creates an empty tar archive with the provided header
 *
 * @param header: the tar header to use
 * @param stats_counter: the stats counter to use for naming files with %d
 */
void create_empty_tar(tar_t* header, const stats_counter_t* stats_counter);

/*
 * Initializes a tar header with the provided stats counter
 *
 * @param header: the tar header to initialize
 * @param stat_counter: the stats counter to use
 */
void init_tar_header(tar_t* header, stats_counter_t* stat_counter);

/*
 * Removes all tar archives in the current directory
 *
 */
void remove_tar_archives();

/*
 * Runs the 'clear' command to clear the terminal
 *
 */
void clear_terminal();

/*
 * Handles the extraction of a tar archive to check whether it crashes or not and updates the stats
 *
 * @param path_extractor: the path to the tar extractor
 * @param crash_counter: the counter to update if the extraction crashed successfully
 * @param stats: the stats table to update
 * @param crash_type: the type of crash that occurred
 * @param field_type: the type of field that caused the crash
 * @param stats_counter: the stats counter to update
 */
int handle_extraction(const char* path_extractor, int* crash_counter, stats_table_t* stats,
                      int crash_type, enum TarHeaderField field_type, stats_counter_t* stats_counter);

#endif
