#ifndef STATS_TABLE_H
#define STATS_TABLE_H

// Defines for maximum array sizes
#define MAX_crash_types 20
#define MAX_FIELD_TYPES 20
#define STATUS_MESSAGE_LENGTH 255

// Structure for a single test tracker
typedef struct test_tracker_t
{
    const char* name; // Name/description of the test
    int count; // Number of scrashes
    int type; // Type identifier
} test_tracker_t;

// Structure for a field tracker
typedef struct field_tracker_t
{
    const char* name; // Name of the field
    int count; // Number of crashes
    int type; // Type identifier
} field_tracker_t;

// Dynamic structure to hold all fuzzing statistics
typedef struct stats_table_t
{
    int total_executions;
    int total_crashes;

    // Dynamic arrays for tracking different types of crashes
    test_tracker_t* crash_types;
    int num_crash_types;

    // Dynamic arrays for tracking field
    field_tracker_t* field_types;
    int num_field_types;
} stats_table_t;


/*
 * Initialize the statistics table
 *
 * @param stats: the statistics table to initialize
 */
void init_stats(stats_table_t* stats);

/*
 * Free the allocated memory for the statistics table
 *
 * @param stats: the statistics table to free
 */
void free_stats(const stats_table_t* stats);

/*
 * Print the statistics table
 *
 * @param stats: the statistics table to print
 * @param current_status: the current status message
 */
void print_stats_table(const stats_table_t* stats, char* current_status);

/*
 * Update the statistics based on the test results
 *
 * @param stats: the statistics table to update
 * @param crash: 1 if the test crashed, 0 otherwise
 * @param crash_type: the type of crash that occurred
 * @param field_type: the type of field that caused the crash
 */
void update_stats(stats_table_t* stats, int crash, int crash_type, int field_type);

/*
 * Add a new crash type to the statistics table
 *
 * @param stats: the statistics table to update
 * @param name: the name of the crash type
 * @param type: the type identifier of the crash
 */
void add_crash_type(stats_table_t* stats, const char* name, int type);

/*
 * Add a new field type to the statistics table
 *
 * @param stats: the statistics table to update
 * @param name: the name of the field type
 * @param type: the type identifier of the field
 */
void add_field_type(stats_table_t* stats, const char* name, int type);

/*
 * Initialize the fuzzing types for the statistics table
 *
 * @param stats: the statistics table to update
 */
void initialize_fuzzing_types(stats_table_t* stats);

/*
 * Update the status message
 *
 * @param status: the new status message
 * @param stats: the statistics table to update
 * @param current_status: the current status message
 */
void update_status(const char* status, const stats_table_t* stats, char* current_status);
#endif // STATS_TABLE_H
