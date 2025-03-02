#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "statstable.h"

#include "constants.h"

// ANSI color codes (keep existing ones)
#define COLOR_RESET   "\033[0m"
#define COLOR_TITLE   "\033[1;36m"
#define COLOR_HEADER  "\033[1;33m"
#define COLOR_NUMBERS "\033[1;32m"
#define COLOR_FRAME   "\033[1;34m"
#define COLOR_STATUS  "\033[1;35m"

static int has_colors = 0;

void check_terminal_support()
{
    const char* term = getenv("TERM");
    if (term)
    {
        has_colors = strstr(term, "xterm") != NULL ||
            strstr(term, "256color") != NULL ||
            strstr(term, "rxvt") != NULL;
    }
}

const char* color(const char* color_code)
{
    return has_colors ? color_code : "";
}

void init_stats(stats_table_t* stats)
{
    stats->total_executions = 0;
    stats->total_crashes = 0;

    // Initialize successful crashes types array
    stats->crash_types = malloc(sizeof(test_tracker_t) * MAX_crash_types);
    stats->num_crash_types = 0;

    // Initialize field types array
    stats->field_types = malloc(sizeof(field_tracker_t) * MAX_FIELD_TYPES);
    stats->num_field_types = 0;

    check_terminal_support();
}

void free_stats(const stats_table_t* stats)
{
    free(stats->crash_types);
    free(stats->field_types);
}

void add_crash_type(stats_table_t* stats, const char* name, const int type)
{
    if (stats->num_crash_types < MAX_crash_types)
    {
        stats->crash_types[stats->num_crash_types].name = name;
        stats->crash_types[stats->num_crash_types].count = 0;
        stats->crash_types[stats->num_crash_types].type = type;
        stats->num_crash_types++;
    }
}

void add_field_type(stats_table_t* stats, const char* name, const int type)
{
    if (stats->num_field_types < MAX_FIELD_TYPES)
    {
        stats->field_types[stats->num_field_types].name = name;
        stats->field_types[stats->num_field_types].count = 0;
        stats->field_types[stats->num_field_types].type = type;
        stats->num_field_types++;
    }
}

void print_stats_table(const stats_table_t* stats, char* current_status)
{
    printf("\r");
    printf("%s+------------------------------------------------------------------------------+%s\r\n",
           color(COLOR_FRAME), color(COLOR_FRAME));

    // Print execution summary
    printf("|%s Execution summary%s                                                            |\r\n",
           color(COLOR_HEADER), color(COLOR_FRAME));
    printf("|%s Status:%s %-69s|\r\n",
           color(COLOR_STATUS), color(COLOR_FRAME), current_status);
    printf("| Total Executions: %s%-7d%s                | Total Crashes: %s%-7d%s            |\r\n",
           color(COLOR_NUMBERS), stats->total_executions, color(COLOR_FRAME),
           color(COLOR_NUMBERS), stats->total_crashes, color(COLOR_FRAME));

    // Print header for split sections
    printf("+------------------------------------------+-----------------------------------+\r\n");
    printf("|%s Crashes Triggered by%s                     |%s Affected Fields%s                   |\r\n",
           color(COLOR_HEADER), color(COLOR_FRAME),
           color(COLOR_HEADER), color(COLOR_FRAME));
    printf("+------------------------------------------+-----------------------------------+\r\n");

    // Print both sections side by side
    const int max_rows = stats->num_crash_types > stats->num_field_types
                             ? stats->num_crash_types
                             : stats->num_field_types;

    for (int i = 0; i < max_rows; i++)
    {
        // Left side (Crashes Triggered by)
        if (i < stats->num_crash_types)
        {
            printf("| %-25s: %s%-7d%s       ",
                   stats->crash_types[i].name,
                   color(COLOR_NUMBERS),
                   stats->crash_types[i].count,
                   color(COLOR_FRAME));
        }
        else
        {
            printf("|                                          ");
        }

        // Right side (Affected Fields)
        if (i < stats->num_field_types)
        {
            printf("| %-14s: %s%-7d%s           |\r\n",
                   stats->field_types[i].name,
                   color(COLOR_NUMBERS),
                   stats->field_types[i].count,
                   color(COLOR_FRAME));
        }
        else
        {
            printf("|                                    |\r\n");
        }
    }

    printf("+------------------------------------------+-----------------------------------+%s\r\n",
           color(COLOR_RESET));

    fflush(stdout);
}

void update_stats(stats_table_t* stats, const int crash, const int crash_type, const int field_type)
{
    stats->total_executions++;
    if (crash)
    {
        stats->total_crashes++;

        // Update crash type counter
        for (int i = 0; i < stats->num_crash_types; i++)
        {
            if (stats->crash_types[i].type == crash_type)
            {
                stats->crash_types[i].count++;
                break;
            }
        }

        // Update field type counter
        for (int i = 0; i < stats->num_field_types; i++)
        {
            if (stats->field_types[i].type == field_type)
            {
                stats->field_types[i].count++;
                break;
            }
        }
    }
}


void initialize_fuzzing_types(stats_table_t* stats)
{
    // Initialize success types (the types of tests we run)
    add_crash_type(stats, "Empty field", CRASH_EMPTY_FIELD);
    add_crash_type(stats, "Non ASCII field", CRASH_NON_ASCII);
    add_crash_type(stats, "Not integer field", CRASH_NON_NUMERIC);
    add_crash_type(stats, "Too short field", CRASH_TOO_SHORT);
    add_crash_type(stats, "Non octal field", CRASH_NON_OCTAL);
    add_crash_type(stats, "Field with null byte", CRASH_NULL_BYTE_MIDDLE);
    add_crash_type(stats, "Field with no null bytes", CRASH_NO_NULL_BYTES);
    add_crash_type(stats, "Field with special char", CRASH_SPECIAL_CHAR);
    add_crash_type(stats, "Field with negative value", CRASH_NEGATIVE_VALUE);
    add_crash_type(stats, "Mode permissions", CRASH_MODE_PERMISSIONS);
    add_crash_type(stats, "Size overflow", CRASH_OVERFLOW);
    add_crash_type(stats, "Integer overflow", CRASH_OVERFLOW_VALUE);
    add_crash_type(stats, "Injection attack", CRASH_INJECTION_ATTACK);
    add_crash_type(stats, "Miscellaneous", CRASH_MISCELLANEOUS);

    // Initialize field types (the fields we test)
    add_field_type(stats, "name field", FIELD_NAME);
    add_field_type(stats, "mode field", FIELD_MODE);
    add_field_type(stats, "uid field", FIELD_UID);
    add_field_type(stats, "gid field", FIELD_GID);
    add_field_type(stats, "size field", FIELD_SIZE);
    add_field_type(stats, "mtime field", FIELD_MTIME);
    add_field_type(stats, "checksum field", FIELD_CHECKSUM);
    add_field_type(stats, "typeflag field", FIELD_TYPEFLAG);
    add_field_type(stats, "linkname field", FIELD_LINKNAME);
    add_field_type(stats, "magic field", FIELD_MAGIC);
    add_field_type(stats, "version field", FIELD_VERSION);
    add_field_type(stats, "uname field", FIELD_UNAME);
    add_field_type(stats, "gname field", FIELD_GNAME);
    add_field_type(stats, "EOF field", FIELD_EOF);
    add_field_type(stats, "Multiple Files", MULTIPLE_FILES);
}

void update_status(const char* status, const stats_table_t* stats, char* current_status)
{
    strncpy(current_status, status, STATUS_MESSAGE_LENGTH);
    printf("\033[H"); // Move to home position
    print_stats_table(stats, current_status);
    fflush(stdout);
}
