/**
 * Hlavickovy soubor pro My MALloc
 * Demonstracni priklad pro 1. ukol IPS/2018
 * Ales Smrcka
 */
#ifndef _MMAL_H
#define _MMAL_H

#include <stdlib.h> // size_t

#ifndef NDEBUG
    // global pointer accessible only in DEBUG mode
    typedef struct header Header;
    struct header {
        Header *next;
        size_t size;
        size_t asize;
    };
    typedef struct arena Arena;
    struct arena {
        Arena *next;
        size_t size;
    };
    extern Arena *first_arena;
    #define PAGE_SIZE (128*1024)
#endif

void *mmalloc(size_t size);
void mfree(void *ptr);
void *mcalloc(size_t size);
void *mrealloc(void *ptr, size_t size);

#endif
