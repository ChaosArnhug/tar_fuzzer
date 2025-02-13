/*
 * tar.h from GNU https://www.gnu.org/software/tar/manual/html_node/Standard.html
 * With padding and sparse headers
 */

#ifndef TAR_H
#define TAR_H

// IMPORTANT: per assignment we don't need to handle the padding for fuzzing just use the 500 bytes posix header no additional 12-bytes struct
typedef struct posix_header
{
    char name[100]; // File name
    char mode[8]; // Permissions (octal string)
    char uid[8]; // Owner UID (octal string)
    char gid[8]; // Group GID (octal string)
    char size[12]; // File size in bytes (octal string)
    char mtime[12]; // Modification time (octal string)
    char chksum[8]; // Checksum for the header
    char typeflag; // File type (one of the TAR_* defines above)
    char linkname[100]; // Name of linked file (if applicable)
    char magic[6]; // "ustar" string
    char version[2]; // Version number "00"
    char uname[32]; // User name (null-terminated string)
    char gname[32]; // Group name (null-terminated string)
    char devmajor[8]; // Major device number (octal string, if special file)
    char devminor[8]; // Minor device number (octal string, if special file)
    char prefix[155]; // Prefix for long file names
    char padding[12]; // Padding to make header size 512 bytes
} posix_header;

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
#define TSUID    04000          /* set UID on execution */
#define TSGID    02000          /* set GID on execution */
#define TSVTX    01000          /* reserved */
/* file permissions */
#define TUREAD   00400          /* read by owner */
#define TUWRITE  00200          /* write by owner */
#define TUEXEC   00100          /* execute/search by owner */
#define TGREAD   00040          /* read by group */
#define TGWRITE  00020          /* write by group */
#define TGEXEC   00010          /* execute/search by group */
#define TOREAD   00004          /* read by other */
#define TOWRITE  00002          /* write by other */
#define TOEXEC   00001          /* execute/search by other */

#define SPARSES_IN_EXTRA_HEADER  16
#define SPARSES_IN_OLDGNU_HEADER 4
#define SPARSES_IN_SPARSE_HEADER 21

#define TAR_BLOCK_SIZE 512

#endif //TAR_H
