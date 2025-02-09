#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int ARCHIVE_NUMBER = 0;

/**
 * Launches another executable given as argument,
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int extract(char* path)
{
    if (path == NULL) return -1;
    int rv = 0;
    char cmd[51];
    strncpy(cmd, path, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

/**
    Generates a default tar header to be used in the fuzzer

    @param header: The tar header structure to be generated
    @param name: The name of the file to be used in the header
*/
void default_tar_header(tar_t* header) {
    memset(header, 0, sizeof(tar_t));

    char name[100];
    snprintf(name, sizeof(name), "archive%d.tar", ARCHIVE_NUMBER);
    strncpy(header->name, name, 100);
    strncpy(header->mode, "07777", 8);
    strncpy(header->uid, "0000000", 8);
    strncpy(header->gid, "0000000", 8);
    strncpy(header->size, "00000000000", 12);
    strncpy(header->mtime, "00000000000", 12);
    header->typeflag = REGTYPE;
    strncpy(header->linkname, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 100);
    strncpy(header->magic, TMAGIC, TMAGLEN);
    strncpy(header->version, TVERSION, TVERSLEN);
    strncpy(header->uname, "name", 32);
    strncpy(header->gname, "name", 32);
    strncpy(header->devmajor, "0000000", 8);
    strncpy(header->devminor, "0000000", 8);
    strncpy(header->prefix, "", 155); // Can be empty as name is less than 100 characters
    calculate_checksum(header);
}

int create_tar_archive(tar_t* header) {
    char name[100];
    snprintf(name, sizeof(name), "archive%d.tar", ARCHIVE_NUMBER++);

    FILE* archive = fopen(name, "wb");
    if (archive == NULL) {
        perror("Error opening file in create_tar_archive");
        return 1;
    }

    if (fwrite(header, sizeof(tar_t), 1, archive) != 1) {
        perror("Error writing to file in create_tar_archive");
        return 1;
    }

    if (fclose(archive) != 0) {
        perror("Error closing file in create_tar_archive");
        return 1;
    }

    return 0;
}

/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_t* entry){
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