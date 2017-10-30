#include "Hasher.h"

string Hasher::makeHash(string values[]) {
    cerr << "RADIUS-PLUGIN: HASHER: generating the key.\n ";

    unsigned char digest[16];
    char text[33];    //The digest.
    gcry_md_hd_t context;                        //the hash context
    int i;
    memset(digest, 0, 16);
    //build the hash

    gcry_md_open(&context, GCRY_MD_MD5, 0);

    int size = sizeof(values) / sizeof(values[0]);

    for (int j = 0; j < size; ++j) {
        cerr << "RADIUS-PLUGIN: HASHER: writing value: " << values[i] << ".\n ";
        gcry_md_write(context, values[i].c_str(), values[i].length());
    }

    memcpy(digest, gcry_md_read(context, GCRY_MD_MD5), 16);

    gcry_md_close(context);

    unsigned int h, l;
    char *p = text;
    unsigned char *c = digest;

    for (i = 0; i < 16; i++) {
        h = *c / 16;
        l = *c % 16;
        c++;
        *p++ = "01234567890ABCDEF"[h];
        *p++ = "01234567890ABCDEF"[l];
    }
    text[32] = '\0';

    cerr << "RADIUS-PLUGIN: HASHER: generated value: " << string(text) << ".\n ";

    return string(text);
}
