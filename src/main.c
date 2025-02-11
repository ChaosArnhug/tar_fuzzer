#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "statstable.h"
#include "constants.h"


// Global variables
StatsTable stats;
char* path_extractor;
char current_status[256] = "Initializing...";

// Structure to define a test set
typedef struct
{
    const char* name;
    int field_type;
    int* test_types;
    int num_test_types;
} TestSet;

/*
 * @brief Prints a status line that overwrites itself at the bottom of the table
 * @param status The status message to print
 */
void update_status(const char* status)
{
    strncpy(current_status, status, sizeof(current_status) - 1);
    printf("\033[H"); // Move to home position
    print_stats_table(&stats);
    printf("\n\033[K"); // Clear the entire line before printing new status
    printf("Status: %s", current_status); // Print status
    printf("\033[K"); // Clear to the end of line
    fflush(stdout);
}

void test_name()
{
    int string_tests[] = {
        CRASH_EMPTY_FIELD,
    };

    update_status("Running Test on field 'name': Fuzzing...");
}

/*
 * @brief This method is purely for the table display and does not perform any fuzzing
 * @param test_set The test set to use for fuzzing
 */
void initialize_fuzzing_types()
{
    // TODO: Add more "category" types as you implement more fuzzing methods
    add_crash_type(&stats, "Empty field", CRASH_EMPTY_FIELD);

    // TODO: Add more "field" types as you implement more fuzzing methods
    add_field_type(&stats, "name field", FIELD_NAME);
}

int main(const int argc, char* argv[])
{
    if (argc != 2 || strlen(argv[1]) == 0)
    {
        printf("Invalid arguments.\n");
        printf("Usage: ./fuzzer <path_to_extractor>\n");
        printf("Example: ./fuzzer ../extractor_x86_64\n");
        return INPUT_ERROR_CODE;
    }

    path_extractor = argv[1];

    struct stat path_stat;
    if (stat(argv[1], &path_stat) != 0)
    {
        fprintf(stderr, "Error: extractor path provided doesn't appear to be a valid file: %s\n", argv[1]);
        return EXTRACTOR_ERROR_CODE;
    }

    if (!S_ISREG(path_stat.st_mode))
    {
        fprintf(stderr, "Error: %s is not a regular file\n", argv[1]);
        return EXTRACTOR_ERROR_CODE;
    }

    if (access(argv[1], X_OK) != 0)
    {
        fprintf(stderr, "Error: no execute permission for %s\n", argv[1]);
        return EXTRACTOR_ERROR_CODE;
    }

    struct timeval timer_start, timer_end;
    gettimeofday(&timer_start, NULL);

    init_stats(&stats);
    initialize_fuzzing_types();

    // Clear screen and initialize display
    printf("\033[2J"); // Clear entire screen
    printf("\033[H"); // Move cursor to home position
    print_stats_table(&stats);

    // TODO: Here we add the fuzzing methods one below another successively. See previous examples for table update logic
    test_name();
    // ...


    // Calculation of the total execution time
    gettimeofday(&timer_end, NULL);
    const double time_used = (double)(timer_end.tv_sec - timer_start.tv_sec) +
        (double)(timer_end.tv_usec - timer_start.tv_usec) / 1000000.0;

    // Print final statistics
    printf("\n\n=== Fuzzing Complete ===\n");
    printf("Execution time: %.2f seconds\n", time_used);
    // Please keep this print statement at the end to ensure the final statistics are displayed properly for potential compatibility issues
    // print_stats_table(&stats);

    return 0;
}
