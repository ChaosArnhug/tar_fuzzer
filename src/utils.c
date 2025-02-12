#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tar.h"

/**
 * Computes the checksum for a tar header and encode it on the header (Teacher function)
 * @param entry: The tar header
 * @return the value of the checksum
 */
 unsigned int calculate_checksum(posix_header* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

void init_posix_header(posix_header* header){
    memset(header, 0, sizeof(struct posix_header));

    strncpy(header->name, "default_name_archive.tar", 100); 
    strncpy(header->mode, "0000644", 8);
    strncpy(header->uid, "0000000", 8);
    strncpy(header->gid, "0000000", 8);
    strncpy(header->size, "00000000000", 12);
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", time(NULL));
    header->typeflag = REGTYPE;
    strncpy(header->linkname, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 100);
    strncpy(header->magic, TMAGIC, TMAGLEN);
    strncpy(header->version, TVERSION, TVERSLEN);
    strncpy(header->uname, "default_user", 32);
    strncpy(header->gname, "default_group", 32);
    // Not sure how we should handle these + padding and size
    strncpy(header->devmajor, "0000000", 8);
    strncpy(header->devminor, "0000000", 8);

    // Could be removed if logic change (+ must be at the end here because checksum of current header content) 
    calculate_checksum(header);
}