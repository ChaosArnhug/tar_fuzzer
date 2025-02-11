#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "statstable.h"

// ANSI color codes (keep existing ones)
#define COLOR_RESET   "\033[0m"
#define COLOR_TITLE   "\033[1;36m"
#define COLOR_HEADER  "\033[1;33m"
#define COLOR_NUMBERS "\033[1;32m"
#define COLOR_FRAME   "\033[1;34m"

static int has_colors = 0;

// Check if terminal supports colors (keep existing function)
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

// Color wrapper function (keep existing function)
const char* color(const char* color_code)
{
    return has_colors ? color_code : "";
}

// Initialize statistics with dynamic arrays
void init_stats(StatsTable* stats)
{
    stats->total_executions = 0;
    stats->total_crashes = 0;

    // Initialize successful crashes types array
    stats->crash_types = malloc(sizeof(TestTracker) * MAX_crash_types);
    stats->num_crash_types = 0;

    // Initialize field types array
    stats->field_types = malloc(sizeof(FieldTracker) * MAX_FIELD_TYPES);
    stats->num_field_types = 0;

    check_terminal_support();
}

// Free allocated memory
void free_stats(const StatsTable* stats)
{
    free(stats->crash_types);
    free(stats->field_types);
}

// Add a new crash type
void add_crash_type(StatsTable* stats, const char* name, const int type)
{
    if (stats->num_crash_types < MAX_crash_types)
    {
        stats->crash_types[stats->num_crash_types].name = name;
        stats->crash_types[stats->num_crash_types].count = 0;
        stats->crash_types[stats->num_crash_types].type = type;
        stats->num_crash_types++;
    }
}

// Add a new field type
void add_field_type(StatsTable* stats, const char* name, const int type)
{
    if (stats->num_field_types < MAX_FIELD_TYPES)
    {
        stats->field_types[stats->num_field_types].name = name;
        stats->field_types[stats->num_field_types].count = 0;
        stats->field_types[stats->num_field_types].type = type;
        stats->num_field_types++;
    }
}

// Print the statistics table
void print_stats_table(const StatsTable* stats)
{
    printf("\r");

    // Print header (keep existing format)
    printf("%s+------------------------------------------------------+\r\n", color(COLOR_FRAME));
    printf("|%s        generation-based tar extractor fuzzer%s         %s|\r\n",
           color(COLOR_TITLE), color(COLOR_FRAME), color(COLOR_FRAME));
    printf("+------------------------------------------------------+\r\n");

    printf("|%s Execution summary%s                                    |\r\n",
           color(COLOR_HEADER), color(COLOR_FRAME));
    printf("| Total Executions: %s%-7d%s                            |\r\n",
           color(COLOR_NUMBERS), stats->total_executions, color(COLOR_FRAME));
    printf("| Total Crashes Detected: %s%-7d%s                      |\r\n",
           color(COLOR_NUMBERS), stats->total_crashes, color(COLOR_FRAME));

    // Print crashes types
    printf("+------------------------------------------------------+\r\n");
    printf("|%s Crashes Triggered by%s                                 |\r\n",
           color(COLOR_HEADER), color(COLOR_FRAME));

    for (int i = 0; i < stats->num_crash_types; i++)
    {
        printf("|  %-25s: %s%-7d%s                  |\r\n",
               stats->crash_types[i].name,
               color(COLOR_NUMBERS),
               stats->crash_types[i].count,
               color(COLOR_FRAME));
    }

    // Print field types
    printf("+------------------------------------------------------+\r\n");
    printf("|%s Affected Fields%s                                      |\r\n",
           color(COLOR_HEADER), color(COLOR_FRAME));

    for (int i = 0; i < stats->num_field_types; i++)
    {
        printf("|  %-14s: %s%-7d%s                             |\r\n",
               stats->field_types[i].name,
               color(COLOR_NUMBERS),
               stats->field_types[i].count,
               color(COLOR_FRAME));
    }

    printf("+------------------------------------------------------+%s\r\n",
           color(COLOR_RESET));

    fflush(stdout);
}

// Update stats based on test results
void update_stats(StatsTable* stats, const int crash, const int crash_type, const int field_type)
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
