#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "statstable.h"
#include "help.h"
#include "constants.h"

void fuzz_field(tar_t* header, char* field_name, const size_t field_size, const enum TarHeaderField field_type,
                stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter, char* current_status)
{
    unsigned int seed;
    if (getentropy(&seed, sizeof(seed)) < 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        seed = (unsigned int)ts.tv_sec ^ (unsigned int)ts.tv_nsec ^ (unsigned int)getpid();
    }

    // 1. Non ascii
    update_status("Starting non-ASCII field test...", stats, current_status);
    const char non_ascii_chars[] = {
        '\xFF', // 255, highest single-byte value
        (char)2144577, // Out-of-range large value
        '\x80', // First non-ASCII byte in extended ASCII
        '\xC0', // Invalid start of UTF-8 sequence
        '\xC1', // Overlong encoding attempt
        '\xF7', // Invalid UTF-8 leading byte
        '\xF8', // Beyond valid UTF-8 range
        '\xFE', // Invalid byte in UTF-8
        '\x81', // High-byte control character
        '\xA0', // Non-breaking space (NBSP)
        '\xAD', // Soft hyphen (invisible in some cases)
        '\xD8', // Lead byte of a UTF-16 surrogate pair
        '\xE0', // Start of a three-byte UTF-8 sequence
        '\xED', // Last valid 3-byte UTF-8 lead (used in surrogates)
        '\xF4', // Start of a four-byte UTF-8 sequence
        '\xFF', // Another invalid byte
        (char)0x110000 // Beyond Unicode valid range (> U+10FFFF)
    };
    for (int i = 0; i < sizeof(non_ascii_chars); i++)
    {
        init_tar_header(header, stats_counter);
        memset(field_name, non_ascii_chars[i], field_size - 1);
        field_name[field_size - 1] = 0;
        create_empty_tar(header, stats_counter);
        if (handle_extraction(path_extractor,
                              &stats_counter->crash_not_ascii_counter,
                              stats, CRASH_NON_ASCII, field_type, stats_counter) != 0)
        {
            break;
        }
    }

    // 2. not integer
    update_status("Starting not integer field test...", stats, current_status);
    const char non_numeric_field[] = "abc";
    init_tar_header(header, stats_counter);
    strncpy(field_name, non_numeric_field, field_size);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_not_integer_counter,
                      stats, CRASH_NON_NUMERIC, field_type, stats_counter);

    // 3. short
    update_status("Starting too short field test...", stats, current_status);
    init_tar_header(header, stats_counter);
    for (int i = 0; i < (int)field_size - 2; i++)
    {
        // generate length -1 random characters
        field_name[i] = (char)('a' + rand_r(&seed) % 26);
    }
    field_name[field_size - 1] = 0;
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_too_short_counter,
                      stats, CRASH_TOO_SHORT, field_type, stats_counter);

    // 4. empty
    update_status("Starting empty field test...", stats, current_status);
    init_tar_header(header, stats_counter);
    strncpy(field_name, "", field_size);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_empty_counter,
                      stats, CRASH_EMPTY_FIELD, field_type, stats_counter);


    // 5. cut in half
    update_status("Starting field cut in half test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, 0, field_size);
    memset(field_name, '1', field_size / 2);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_cut_middle_counter,
                      stats, CRASH_CUT_MIDDLE, field_type, stats_counter);

    // 6. Not terminated by null byte
    update_status("Starting field not terminated by null byte test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, '5', field_size);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_not_ending_with_null_byte_counter,
                      stats, CRASH_NO_NULL_BYTES, field_type, stats_counter);

    // 7. all null bytes
    update_status("Starting field with null byte in the middle test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, 0, field_size);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_null_byte_in_the_middle_counter,
                      stats, CRASH_NULL_BYTE_MIDDLE, field_type, stats_counter);

    // 8. set all null bytes except last one
    update_status("Starting field with null byte in the middle test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, 0, field_size - 1);
    field_name[field_size - 1] = '0';
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_null_byte_in_the_middle_counter,
                      stats, CRASH_NULL_BYTE_MIDDLE, field_type, stats_counter);

    // 9. Some null byte in middle but not ending in one
    update_status("Starting field with null byte in the middle test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, '0', field_size - 1);
    field_name[field_size - 1] = 0;
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_null_byte_in_the_middle_counter,
                      stats, CRASH_NULL_BYTE_MIDDLE, field_type, stats_counter);

    // 10. Some null byte in middle
    update_status("Starting field with null byte in the middle test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, 0, field_size);
    memset(field_name, '0', field_size / 2);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_null_byte_in_the_middle_counter,
                      stats, CRASH_NULL_BYTE_MIDDLE, field_type, stats_counter);


    // 11. No null byte
    update_status("Starting field with no null bytes test...", stats, current_status);
    init_tar_header(header, stats_counter);
    const size_t first_term = strnlen(field_name, field_size);

    if (first_term < field_size)
    {
        memset(field_name + first_term, ' ', field_size - first_term);
    }
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_no_null_bytes_counter,
                      stats, CRASH_NO_NULL_BYTES, field_type, stats_counter);

    // 12. Non-octal
    update_status("Starting non-octal field test...", stats, current_status);
    init_tar_header(header, stats_counter);
    memset(field_name, '9', field_size - 1);
    field_name[field_size - 1] = 0;
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_not_octal_counter,
                      stats, CRASH_NON_OCTAL, field_type, stats_counter);

    // 13. Special characters still in ascii
    update_status("Starting field with special ASCII character test...", stats, current_status);
    const char special_chars[] = {'\"', '\'', ' ', '\t', '\r', '\n', '\v', '\f', '\b'};
    for (int i = 0; i < (int)sizeof(special_chars); i++)
    {
        init_tar_header(header, stats_counter);
        memset(field_name, special_chars[i], field_size - 1);
        field_name[field_size - 1] = 0;
        create_empty_tar(header, stats_counter);
        handle_extraction(path_extractor,
                          &stats_counter->crash_special_character_counter,
                          stats, CRASH_SPECIAL_CHAR, field_type, stats_counter);
    }

    // 14. Negative value
    update_status("Starting field with negative value test...", stats, current_status);
    init_tar_header(header, stats_counter);
    snprintf(field_name, field_size, "%d", INT_MIN);
    create_empty_tar(header, stats_counter);
    handle_extraction(path_extractor,
                      &stats_counter->crash_negative_value_counter,
                      stats, CRASH_NEGATIVE_VALUE, field_type, stats_counter);
}

void name_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                  char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.name, sizeof(header.name), FIELD_NAME, stats, path_extractor, stats_counter,
               current_status);
    stats_counter->name_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void mode_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                  char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;

    // Standard fuzzing
    fuzz_field(&header, header.mode, sizeof(header.mode), FIELD_MODE, stats, path_extractor, stats_counter,
               current_status);

    // Fuzzing with valid modes
    const size_t num_modes = sizeof(tar_modes) / sizeof(tar_modes[0]);
    for (size_t i = 0; i < num_modes; i++)
    {
        char mode_str[sizeof(header.mode)];
        init_tar_header(&header, stats_counter);

        // Format mode as octal string with error checking
        if (snprintf(mode_str, sizeof(mode_str), "%04o", tar_modes[i]) < 0)
        {
            continue; // Skip if formatting fails
        }

        if (strncpy(header.mode, mode_str, sizeof(header.mode)) != header.mode)
        {
            continue; // Skip if copy fails
        }

        create_empty_tar(&header, stats_counter);
        handle_extraction(path_extractor, &stats_counter->crash_mode_permission_counter, stats, CRASH_MODE_PERMISSIONS,
                          FIELD_MODE, stats_counter);
    }

    stats_counter->mode_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void uid_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter, char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.uid, sizeof(header.uid), FIELD_UID, stats, path_extractor, stats_counter,
               current_status);
    stats_counter->uid_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void gid_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter, char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.gid, sizeof(header.gid), FIELD_GID, stats, path_extractor, stats_counter,
               current_status);
    stats_counter->gid_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void size_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                  char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.size, sizeof(header.size), FIELD_SIZE, stats, path_extractor, stats_counter,
               current_status);

    const char content_header[] = "----";
    const int content_header_size = sizeof(content_header);

    const int number_of_try = 10;
    int possible_size[number_of_try];
    unsigned int seed;
    if (getentropy(&seed, sizeof(seed)) < 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        seed = (unsigned int)ts.tv_sec ^ (unsigned int)ts.tv_nsec;
    }
    for (int i = 0; i < number_of_try; i++)
    {
        possible_size[i] = rand_r(&seed) % LENGTH_TAR_BLOCK;
    }

    for (int i = 0; i < number_of_try; i++)
    {
        init_tar_header(&header, stats_counter);
        const char end_data[LENGTH_TAR_BLOCK] = {0}; // Zero initialization
        snprintf(header.size, sizeof(header.size), "%o", possible_size[i]);
        create_tar(&header, content_header, content_header_size, end_data, LENGTH_TAR_BLOCK, stats_counter);
        handle_extraction(path_extractor, &stats_counter->crash_size_counter, stats, CRASH_OVERFLOW, FIELD_SIZE,
                          stats_counter);
    }

    init_tar_header(&header, stats_counter);
    snprintf(header.size, sizeof(header.size), "%d", INT_MIN);
    const char end_data[LENGTH_TAR_BLOCK] = {0}; // Zero initialization
    create_tar(&header, content_header, content_header_size, end_data, LENGTH_TAR_BLOCK, stats_counter);
    handle_extraction(path_extractor, &stats_counter->crash_size_counter, stats, CRASH_NEGATIVE_VALUE,
                      FIELD_SIZE, stats_counter);
    stats_counter->size_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void create_header_with_time(const time_t time, stats_table_t* stats, char* path_extractor,
                             stats_counter_t* stats_counter, char* current_status)
{
    tar_t header;
    char time_string[sizeof(header.mtime)];
    init_tar_header(&header, stats_counter);
    snprintf(time_string, sizeof(header.mtime), "%lo", time);
    strncpy(header.mtime, time_string, sizeof(header.mtime));
    create_empty_tar(&header, stats_counter);
    //handle_extraction(path_extractor, &stats_counter->successful_with_size, stats, CRASH_OVERFLOW, FIELD_SIZE, stats_counter);
    // TODO change
}

void mtime_fuzzing(stats_table_t* stats, char* path_extractor, stats_counter_t* stats_counter, char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    const time_t now = time(NULL);
    fuzz_field(&header, header.mtime, sizeof(header.mtime), FIELD_MTIME, stats, path_extractor, stats_counter,
               current_status);

    // Test with the current time
    create_header_with_time(now, stats, path_extractor, stats_counter, current_status);
    // Test with the minimum value for an int
    create_header_with_time(INT_MIN, stats, path_extractor, stats_counter, current_status);

    // Test with the date 1 year in the past
    const time_t one_year_ago = now - 365 * 24 * 60 * 60;
    create_header_with_time(one_year_ago, stats, path_extractor, stats_counter, current_status);

    create_header_with_time(-1, stats, path_extractor, stats_counter, current_status);

    // Test with the date 1 second after 1970
    create_header_with_time(1, stats, path_extractor, stats_counter, current_status);

    // Test with the date 1 month in the future
    const time_t one_month_from_now = now + 30 * 24 * 60 * 60;
    create_header_with_time(one_month_from_now, stats, path_extractor, stats_counter, current_status);

    // Test with the maximum value for an int
    const time_t max_int_time = now + INT_MAX;
    create_header_with_time(max_int_time, stats, path_extractor, stats_counter, current_status);

    // Test with the maximum value for a long int
    const time_t max_long_long_time = now + LLONG_MAX;
    create_header_with_time(max_long_long_time, stats, path_extractor, stats_counter, current_status);

    stats_counter->mtime_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void chksum_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                    char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.chksum, sizeof(header.chksum), FIELD_CHECKSUM, stats, path_extractor, stats_counter,
               current_status);

    const char content_header[] = "XXX";
    const int content_header_size = sizeof(content_header);
    char end_data[LENGTH_TAR_BLOCK];
    init_tar_header(&header, stats_counter);
    memset(&header.chksum, 0, 1);
    create_tar(&header, content_header, content_header_size, end_data, LENGTH_TAR_BLOCK, stats_counter);
    //extract(path_extractor);

    stats_counter->checksum_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void typeflag_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                      char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;

    // 1. Try every value until 255 (1 byte)
    for (int i = 0; i < 256; i++)
    {
        init_tar_header(&header, stats_counter);
        header.typeflag = (char)i;
        create_empty_tar(&header, stats_counter);
        handle_extraction(path_extractor,
                          &stats_counter->typeflag_field_vulnerabilities_counter,
                          stats, CRASH_SPECIAL_CHAR, FIELD_TYPEFLAG, stats_counter);
    }

    // 2. Try -1
    init_tar_header(&header, stats_counter);
    header.typeflag = -1;
    create_empty_tar(&header, stats_counter);
    handle_extraction(path_extractor, &stats_counter->typeflag_field_vulnerabilities_counter, stats,
                      CRASH_CHAR_OVERFLOW,
                      FIELD_TYPEFLAG, stats_counter);

    // 3. try non ascii
    init_tar_header(&header, stats_counter);
    header.typeflag = '\xFF';
    create_empty_tar(&header, stats_counter);
    handle_extraction(path_extractor, &stats_counter->typeflag_field_vulnerabilities_counter, stats, CRASH_SPECIAL_CHAR,
                      FIELD_TYPEFLAG, stats_counter);
    stats_counter->typeflag_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void linkname_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                      char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.linkname, sizeof(header.linkname), FIELD_LINKNAME, stats, path_extractor,
               stats_counter, current_status);

    stats_counter->linkname_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void magic_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                   char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.magic, sizeof(header.magic), FIELD_MAGIC, stats, path_extractor, stats_counter,
               current_status);
    stats_counter->magic_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void version_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                     char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.version, sizeof(header.version), FIELD_VERSION, stats, path_extractor, stats_counter,
               current_status);
    // 1. Try all possible octal values for the version field
    char octal[3] = {'0', '0', '\0'};

    for (int i = 0; i < 8; i++)
    {
        octal[0] = (char)(i + '0');
        for (int j = 0; j < 8; j++)
        {
            octal[1] = (char)(j + '0');

            init_tar_header(&header, stats_counter);
            strncpy(header.version, octal, sizeof(header.version));
            create_empty_tar(&header, stats_counter);
            //extract(path_extractor);
        }
    }

    // 2. Try all possible octal values for the version field
    for (int i = -1; i >= -8; i--)
    {
        octal[0] = (char)(i + '0');
        for (int j = -1; j >= -8; j--)
        {
            octal[1] = (char)(j + '0');

            init_tar_header(&header, stats_counter);
            strncpy(header.version, octal, sizeof(header.version));
            create_empty_tar(&header, stats_counter);
            //extract(path_extractor);
        }
    }

    stats_counter->version_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void uname_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                   char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.uname, sizeof(header.uname), FIELD_UNAME, stats, path_extractor, stats_counter,
               current_status);

    stats_counter->uname_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void gname_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                   char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;
    fuzz_field(&header, header.gname, sizeof(header.gname), FIELD_GNAME, stats, path_extractor, stats_counter,
               current_status);

    stats_counter->gname_field_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}

void end_of_file_fuzzing(stats_table_t* stats, const char* path_extractor, stats_counter_t* stats_counter,
                         char* current_status)
{
    tar_t header;
    const int current_crash_counter = stats_counter->crash_counter;

    const int end_data_sizes[] = {
        0, 1, END_BYTES / 4, END_BYTES / 2, END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2, END_BYTES * 4
    };
    const int sizeof_array = sizeof(end_data_sizes) / sizeof(int);

    char end_data[end_data_sizes[sizeof_array - 1]];
    memset(end_data, 0, end_data_sizes[sizeof_array - 1]);
    const char content_header[] = "XXXXXXXXXXXXXXXXXXXXXXXXX";

    int i = 0;
    while (i < sizeof_array)
    {
        const int content_header_size = sizeof(content_header);
        init_tar_header(&header, stats_counter);
        create_tar(&header, NULL, 0, end_data, end_data_sizes[i], stats_counter);
        // Create a tar file with no file content
        //extract(path_extractor);

        init_tar_header(&header, stats_counter);
        snprintf(header.size, sizeof(header.size), "%o", content_header_size);
        create_tar(&header, content_header, content_header_size, end_data, end_data_sizes[i], stats_counter);
        // Create a tar file with the dummy text
        //extract(path_extractor);
        i++;
    }

    stats_counter->eof_vulnerabilities_counter += stats_counter->crash_counter - current_crash_counter;
}


int main(const int argc, char* argv[])
{
    remove_tar_archives();
    char* path_extractor = NULL; // Initialize to NULL

    if (argc != 2 || argv[1] == NULL || strlen(argv[1]) == 0)
    {
        path_extractor = "./extractor";
        printf("No valid path provided, trying default path: %s\n", path_extractor);
    }
    else
    {
        path_extractor = argv[1];
    }

    struct stat path_stat;
    if (stat(path_extractor, &path_stat) != 0)
    {
        fprintf(stderr, "Error: extractor path doesn't appear to be a valid file: %s\n", path_extractor);
        if (argc != 2 || argv[1] == NULL || strlen(argv[1]) == 0)
        {
            printf("Usage: ./fuzzer <path_to_extractor>\n");
            printf("Example: ./fuzzer ../extractor_x86_64\n");
        }
        return EXTRACTOR_ERROR_CODE;
    }

    if (!S_ISREG(path_stat.st_mode))
    {
        fprintf(stderr, "Error: %s is not a regular file\n", path_extractor);
        return EXTRACTOR_ERROR_CODE;
    }

    if (access(path_extractor, X_OK) != 0)
    {
        fprintf(stderr, "Error: no execute permission for %s\n", path_extractor);
        return EXTRACTOR_ERROR_CODE;
    }

    struct timeval timer_start, timer_end;
    gettimeofday(&timer_start, NULL);
    clear_terminal();
    stats_counter_t stats_counter;
    init_stats_counter(&stats_counter);

    stats_table_t stats;
    char current_status[256];
    init_stats(&stats);
    initialize_fuzzing_types(&stats);

    name_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    mode_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    uid_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    gid_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    size_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    mtime_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    chksum_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    typeflag_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    linkname_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    magic_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    version_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    uname_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    gname_fuzzing(&stats, path_extractor, &stats_counter, current_status);
    end_of_file_fuzzing(&stats, path_extractor, &stats_counter, current_status);

    gettimeofday(&timer_end, NULL);
    const double time_used = (double)(timer_end.tv_sec - timer_start.tv_sec) +
        (double)(timer_end.tv_usec - timer_start.tv_usec) / 1000000.0;

    char final_status_buffer[STATUS_MESSAGE_LENGTH];
    snprintf(final_status_buffer, sizeof(final_status_buffer), "Fuzzing Complete. Execution time: %.2f seconds",
             time_used);
    update_status(final_status_buffer, &stats, current_status);

    remove_tar_archives();
    return 0;
}
