#ifndef CONSTANTS_H
#define CONSTANTS_H

#define INPUT_ERROR_CODE (-1)
#define EXTRACTOR_ERROR_CODE (-2)


#define DEFAULT_MODE_FIELD "0777"
#define DEFAULT_UNIX_USER "root"
#define DEFAULT_UNIX_USER_ID "0000000"
#define DEFAULT_UNIX_GROUP_ID "0000000"

#define HEADER_LENGTH 512
#define LENGTH_TAR_BLOCK 512
#define LENGTH_POSIX_HEADER 500
#define END_BYTES 1024 // "At the end of the archive there are two 512-bytes blocks filled with binary zeros as an end-of-file marker"



#define LENGTH_NAME      100
#define LENGTH_MODE      8
#define LENGTH_UID       8
#define LENGTH_GID       8
#define LENGTH_SIZE      12
#define LENGTH_MTIME     12
#define LENGTH_CHKSUM    8
#define LENGTH_LINKNAME  100
#define LENGTH_MAGIC     6
#define LENGTH_VERSION   2
#define LENGTH_UNAME     32
#define LENGTH_GNAME     32
#define LENGTH_DEVMAJOR  8
#define LENGTH_DEVMINOR  8
#define LENGTH_PREFIX    155
#define LENGTH_PADDING  (LENGTH_TAR_BLOCK - LENGTH_POSIX_HEADER) // 12 here

static const char TAR_FIELD_NAME[] = "name";
static const char TAR_FIELD_MODE[] = "mode";
static const char TAR_FIELD_UID[] = "uid";
static const char TAR_FIELD_GID[] = "gid";
static const char TAR_FIELD_SIZE[] = "size";
static const char TAR_FIELD_MTIME[] = "mtime";
static const char TAR_FIELD_CHKSUM[] = "chksum";
static const char TAR_FIELD_TYPEFLAG[] = "typeflag";
static const char TAR_FIELD_LINKNAME[] = "linkname";
static const char TAR_FIELD_MAGIC[] = "magic";
static const char TAR_FIELD_VERSION[] = "version";
static const char TAR_FIELD_UNAME[] = "uname";
static const char TAR_FIELD_GNAME[] = "gname";
static const char TAR_FIELD_DEVMAJOR[] = "devmajor";
static const char TAR_FIELD_DEVMINOR[] = "devminor";
static const char TAR_FIELD_PREFIX[] = "prefix";

static const char* keep_files[] = {
    ".gitignore",
    "constants.h",
    "extractor",
    "extractor_x86_64",
    "fuzzer",
    "help.c",
    "main.c",
    "Makefile",
    "README.md",
    "help.h",
    "statstable.c",
    "statstable.h",
    "success_*",
    "cmake_install.cmake",
    "CMakeCache.txt",
    "CMakeLists.txt",
};

static const char* exclude_paths[] = {
    "./.",
    "./..",
    "./src",
    "./src/*",
    "./.git",
    "./.idea",
    "./.git/*",
    "./.idea/*"
};


#define TMAGIC   "ustar"        /* ustar and a null */
#define TMAGLEN  6
#define TVERSION "00"           /* 00 and no null */
#define TVERSLEN 2

/* Values used in typeflag field.  */
#define REGTYPE  '0'            /* regular file */
#define AREGTYPE '\0'           /* regular file */
#define LNKTYPE  '1'            /* link */
#define SYMTYPE  '2'            /* reserved */
#define CHRTYPE  '3'            /* character special */
#define BLKTYPE  '4'            /* block special */
#define DIRTYPE  '5'            /* directory */
#define FIFOTYPE '6'            /* FIFO special */
#define CONTTYPE '7'            /* reserved */

#define XHDTYPE  'x'            /* Extended header referring to the next file in the archive */
#define XGLTYPE  'g'            /* Global extended header */

/* Bits used in the mode field, values in octal.  */
enum TarMode
{
    TSUID = 04000, /* set UID on execution */
    TSGID = 02000, /* set GID on execution */
    TSVTX = 01000, /* reserved */
    TUREAD = 00400, /* read by owner */
    TUWRITE = 00200, /* write by owner */
    TUEXEC = 00100, /* execute/search by owner */
    TGREAD = 00040, /* read by group */
    TGWRITE = 00020, /* write by group */
    TGEXEC = 00010, /* execute/search by group */
    TOREAD = 00004, /* read by other */
    TOWRITE = 00002, /* write by other */
    TOEXEC = 00001 /* execute/search by other */
};

static enum TarMode tar_modes[] = {
    TSUID, TSGID, TSVTX, TUREAD, TUWRITE, TUEXEC, TGREAD, TGWRITE, TGEXEC, TOREAD, TOWRITE, TOEXEC
};

#define CRASH_EMPTY_FIELD         0
#define CRASH_NON_ASCII          1
#define CRASH_NON_NUMERIC        2
#define CRASH_TOO_SHORT          3
#define CRASH_NON_OCTAL          4
#define CRASH_CUT_MIDDLE         5
#define CRASH_NULL_BYTE_MIDDLE   6
#define CRASH_NO_NULL_BYTES      7
#define CRASH_SPECIAL_CHAR       8
#define CRASH_NEGATIVE_VALUE     9
#define CRASH_CHAR_OVERFLOW      10
#define CRASH_MODE_PERMISSIONS   11
#define CRASH_OVERFLOW          12
#define CRASH_OVERFLOW_VALUE 13
#define CRASH_INJECTION_ATTACK 14
#define CRASH_MISCELLANEOUS 15

enum TarHeaderField
{
    FIELD_NAME = 0,
    FIELD_MODE = 1,
    FIELD_UID = 2,
    FIELD_GID = 3,
    FIELD_SIZE = 4,
    FIELD_MTIME = 5,
    FIELD_CHECKSUM = 6,
    FIELD_TYPEFLAG = 7,
    FIELD_LINKNAME = 8,
    FIELD_MAGIC = 9,
    FIELD_VERSION = 10,
    FIELD_UNAME = 11,
    FIELD_GNAME = 12,
    FIELD_EOF = 13,
    MULTIPLE_FILES = 14
};

#endif
