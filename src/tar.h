/*
 * tar.h from GNU https://www.gnu.org/software/tar/manual/html_node/Standard.html
 * With padding and sparse headers
 */

#ifndef TAR_H
#define TAR_H

union tar_padding
{
    char bytes[12];
};

#pragma pack(push, 1)
typedef struct posix_header
{
    char name[100]; // File name
    char mode[8]; // Permissions (octal string)
    char uid[8]; // Owner UID (octal string)
    char gid[8]; // Group GID (octal string)
    char size[12]; // File size in bytes (octal string)
    char mtime[12]; // Modification time (octal string)
    char chksum[8]; // Checksum for the header
    char typeflag[1]; // File type (one of the TAR_* defines above)
    char linkname[100]; // Name of linked file (if applicable)
    char magic[6]; // "ustar" string
    char version[2]; // Version number "00"
    char uname[32]; // User name (null-terminated string)
    char gname[32]; // Group name (null-terminated string)
    char devmajor[8]; // Major device number (octal string, if special file)
    char devminor[8]; // Minor device number (octal string, if special file)
    char prefix[155]; // Prefix for long file names
    union tar_padding padding;
} posix_header;
#pragma pack(pop)

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

#define XHDTYPE  'x'            /* Extended header referring to the
next file in the archive */
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

struct sparse
{
    /* byte offset */
    char offset[12]; /*   0 */
    char numbytes[12]; /*  12 */
    /*  24 */
};

struct sparse_header
{
    /* byte offset */
    struct sparse sp[SPARSES_IN_SPARSE_HEADER];
    /*   0 */
    char isextended; /* 504 */
    /* 505 */
};

#define OLDGNU_MAGIC "ustar  "  /* 7 chars and a null */

struct oldgnu_header
{
    /* byte offset */
    char unused_pad1[345]; /*   0 */
    char atime[12]; /* 345 Incr. archive: atime of the file */
    char ctime[12]; /* 357 Incr. archive: ctime of the file */
    char offset[12]; /* 369 Multivolume archive: the offset of
                                     the start of this volume */
    char longnames[4]; /* 381 Not used */
    char unused_pad2; /* 385 */
    struct sparse sp[SPARSES_IN_OLDGNU_HEADER];
    /* 386 */
    char isextended; /* 482 Sparse file: Extension sparse header
                                     follows */
    char realsize[12]; /* 483 Sparse file: Real size*/
    /* 495 */
};

/* This is a dir entry that contains the names of files that were in the
   dir at the time the dump was made.  */
#define GNUTYPE_DUMPDIR 'D'

/* Identifies the *next* file on the tape as having a long linkname.  */
#define GNUTYPE_LONGLINK 'K'

/* Identifies the *next* file on the tape as having a long name.  */
#define GNUTYPE_LONGNAME 'L'

/* This is the continuation of a file that began on another volume.  */
#define GNUTYPE_MULTIVOL 'M'

/* This is for sparse files.  */
#define GNUTYPE_SPARSE 'S'

/* This file is a tape/volume header.  Ignore it on extraction.  */
#define GNUTYPE_VOLHDR 'V'

/* Solaris extended header */
#define SOLARIS_XHDTYPE 'X'

/* Jörg Schilling star header */

struct star_header
{
    /* byte offset */
    char name[100]; /*   0 */
    char mode[8]; /* 100 */
    char uid[8]; /* 108 */
    char gid[8]; /* 116 */
    char size[12]; /* 124 */
    char mtime[12]; /* 136 */
    char chksum[8]; /* 148 */
    char typeflag; /* 156 */
    char linkname[100]; /* 157 */
    char magic[6]; /* 257 */
    char version[2]; /* 263 */
    char uname[32]; /* 265 */
    char gname[32]; /* 297 */
    char devmajor[8]; /* 329 */
    char devminor[8]; /* 337 */
    char prefix[131]; /* 345 */
    char atime[12]; /* 476 */
    char ctime[12]; /* 488 */
    /* 500 */
};

#define SPARSES_IN_STAR_HEADER      4
#define SPARSES_IN_STAR_EXT_HEADER  21

struct star_in_header
{
    char fill[345]; /*   0  Everything that is before t_prefix */
    char prefix[1]; /* 345  t_name prefix */
    char fill2; /* 346  */
    char fill3[8]; /* 347  */
    char isextended; /* 355  */
    struct sparse sp[SPARSES_IN_STAR_HEADER]; /* 356  */
    char realsize[12]; /* 452  Actual size of the file */
    char offset[12]; /* 464  Offset of multivolume contents */
    char atime[12]; /* 476  */
    char ctime[12]; /* 488  */
    char mfill[8]; /* 500  */
    char xmagic[4]; /* 508  "tar" */
};

struct star_ext_header
{
    struct sparse sp[SPARSES_IN_STAR_EXT_HEADER];
    char isextended;
};

#endif //TAR_H
