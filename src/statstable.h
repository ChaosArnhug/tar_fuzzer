#ifndef STATS_TABLE_H
#define STATS_TABLE_H

// Defines for maximum array sizes
#define MAX_crash_types 20
#define MAX_FIELD_TYPES 20

// Structure for a single test tracker
typedef struct
{
    const char* name; // Name/description of the test
    int count; // Number of scrashes
    int type; // Type identifier
} TestTracker;

// Structure for a field tracker
typedef struct
{
    const char* name; // Name of the field
    int count; // Number of crashes
    int type; // Type identifier
} FieldTracker;

// Dynamic structure to hold all fuzzing statistics
typedef struct
{
    int total_executions;
    int total_crashes;

    // Dynamic arrays for tracking different types of crashes
    TestTracker* crash_types;
    int num_crash_types;

    // Dynamic arrays for tracking field
    FieldTracker* field_types;
    int num_field_types;
} StatsTable;

// TODO: Add more "category" types as you implement more fuzzing methods
#define CRASH_EMPTY_FIELD         0

// TODO: Add more "field" types as you implement more fuzzing methods
#define FIELD_NAME                 0

// Function prototypes
void init_stats(StatsTable* stats);
void free_stats(const StatsTable* stats);
void print_stats_table(const StatsTable* stats);
void update_stats(StatsTable* stats, int crash, int crash_type, int field_type);
void add_crash_type(StatsTable* stats, const char* name, int type);
void add_field_type(StatsTable* stats, const char* name, int type);

#endif // STATS_TABLE_H
