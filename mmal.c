/**
 * Implementace My MALloc
 * Demonstracni priklad pro 1. ukol IPS/2018
 * Ales Smrcka
 */

#include "mmal.h"
#include <sys/mman.h> // mmap
#include <stdbool.h> // bool
#include <assert.h> // assert
//#include <stdio.h> // TODO DELETE
//#include <errno.h> // TODO DELETE
//#include <string.h> // TODO DELETE

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifdef NDEBUG
/**
 * The structure header encapsulates data of a single memory block.
 *   ---+------+----------------------------+---
 *      |Header|DDD not_free DDDDD...free...|
 *   ---+------+-----------------+----------+---
 *             |-- Header.asize -|
 *             |-- Header.size -------------|
 */
typedef struct header Header;
struct header {

    /**
     * Pointer to the next header. Cyclic list. If there is no other block,
     * points to itself.
     */
    Header *next;

    /// size of the block
    size_t size;

    /**
     * Size of block in bytes allocated for program. asize=0 means the block 
     * is not used by a program.
     */
    size_t asize;
};

/**
 * The arena structure.
 *   /--- arena metadata
 *   |     /---- header of the first block
 *   v     v
 *   +-----+------+-----------------------------+
 *   |Arena|Header|.............................|
 *   +-----+------+-----------------------------+
 *
 *   |--------------- Arena.size ---------------|
 */
typedef struct arena Arena;
struct arena {

    /**
     * Pointer to the next arena. Single-linked list.
     */
    Arena *next;

    /// Arena size.
    size_t size;
};

#define PAGE_SIZE (128*1024)

#endif // NDEBUG

Arena *first_arena = NULL;

/**
 * Return size alligned to PAGE_SIZE
 */
static
size_t allign_page(size_t size)
{
    return ((size - 1) / PAGE_SIZE + 1) * PAGE_SIZE;
}

/**
 * Allocate a new arena using mmap.
 * @param req_size requested size in bytes. Should be alligned to PAGE_SIZE.
 * @return pointer to a new arena, if successfull. NULL if error.
 * @pre req_size > sizeof(Arena) + sizeof(Header)
 */

/**
 *   +-----+------------------------------------+
 *   |Arena|....................................|
 *   +-----+------------------------------------+
 *
 *   |--------------- Arena.size ---------------|
 */
static
Arena *arena_alloc(size_t req_size)
{
    assert(req_size > sizeof(Arena) + sizeof(Header));

    req_size = allign_page(req_size);

    Arena *arena = mmap(
        NULL,
	req_size,
	PROT_READ | PROT_WRITE,
	MAP_ANONYMOUS | MAP_PRIVATE,
	-1,
	0
    ); // FIXME

    if (arena == MAP_FAILED)
        return NULL;

    arena->next = NULL;
    arena->size = req_size;
    return arena;
}

/**
 * Appends a new arena to the end of the arena list.
 * @param a     already allocated arena
 */
static
void arena_append(Arena *a)
{
    Arena *arena = first_arena;
    if (!first_arena) {
        first_arena = a;
        return;
    }
    while (arena->next)
        arena = arena->next;

    arena->next = a;
}

/**
 * Header structure constructor (alone, not used block).
 * @param hdr       pointer to block metadata.
 * @param size      size of free block
 * @pre size > 0
 */
/**
 *   +-----+------+------------------------+----+
 *   | ... |Header|........................| ...|
 *   +-----+------+------------------------+----+
 *
 *                |-- Header.size ---------|
 */
static
void hdr_ctor(Header *hdr, size_t size)
{
    assert(size > 0);
    hdr->next = NULL;
    hdr->size = size;
    hdr->asize = 0;
}

/**
 * Checks if the given free block should be split in two separate blocks.
 * @param hdr       header of the free block
 * @param size      requested size of data
 * @return true if the block should be split
 * @pre hdr->asize == 0
 * @pre size > 0
 */
static
bool hdr_should_split(Header *hdr, size_t size)
{
    assert(hdr->asize == 0);
    assert(size > 0);
    return (hdr->size - size) >= (sizeof(Header) + 4);
}

/**
 * Splits one block in two.
 * @param hdr       pointer to header of the big block
 * @param req_size  requested size of data in the (left) block.
 * @return pointer to the new (right) block header.
 * @pre   (hdr->size >= req_size + 2*sizeof(Header))
 */
/**
 * Before:        |---- hdr->size ---------|
 *
 *    -----+------+------------------------+----
 *         |Header|........................|
 *    -----+------+------------------------+----
 *            \----hdr->next---------------^
 */
/**
 * After:         |- req_size -|
 *
 *    -----+------+------------+------+----+----
 *     ... |Header|............|Header|....|
 *    -----+------+------------+------+----+----
 *             \---next--------^  \--next--^
 */
static
Header *hdr_split(Header *hdr, size_t req_size)
{
    assert((hdr->size >= req_size + 2*sizeof(Header)));
    Header *p = hdr;
    p = (void*) p + sizeof(Header) + req_size;

    if (hdr->next)
        p->next = hdr->next;
    else //if there is only hdr
        p->next = hdr;
    hdr->next = p;

    p->size = hdr->size - req_size - sizeof(Header);
    p->asize = 0;
    hdr->size = req_size;

    return p;
}

/**
 * Detect if two adjacent blocks could be merged.
 * @param left      left block
 * @param right     right block
 * @return true if two block are free and adjacent in the same arena.
 * @pre left->next == right
 * @pre left != right
 */
static
bool hdr_can_merge(Header *left, Header *right)
{
    assert(left->next == right);
    assert(left != right);
    return (!(left->asize) && !(right->asize));
}

/**
 * Merge two adjacent free blocks.
 * @param left      left block
 * @param right     right block
 * @pre left->next == right
 * @pre left != right
 */
static
void hdr_merge(Header *left, Header *right)
{
    assert(left->next == right);
    assert(left != right);

    if (right->next != left)
        left->next = right->next;
    else
        left->next = NULL;
    left->size = left->size + right->size + sizeof(Header);
}

/**
 * Finds the first free block that fits to the requested size.
 * @param size      requested size
 * @return pointer to the header of the block or NULL if no block is available.
 * @pre size > 0
 */
static
Header *first_fit(size_t size)
{
    Header *hdr = (void *) first_arena + sizeof(Arena);
    Header *first = hdr;
    while (hdr->asize || (hdr->size < size)) {
        hdr = hdr->next;
        if (hdr == first || !hdr)
            return NULL;
    }

    return hdr;
}

/**
 * Search the header which is the predecessor to the hdr. Note that if 
 * @param hdr       successor of the search header
 * @return pointer to predecessor, hdr if there is just one header.
 * @pre first_arena != NULL
 * @post predecessor->next == hdr
 */
static
Header *hdr_get_prev(Header *hdr)
{
    assert(first_arena != NULL);
    if (!(hdr->next) || (hdr->next == hdr))
        return NULL;

    Header *tmp = hdr;
    while (tmp->next != hdr)
        tmp = tmp->next;
    return tmp;
}

/**
 * Allocate memory. Use first-fit search of available block.
 * @param size      requested size for program
 * @return pointer to allocated data or NULL if error or size = 0.
 */
void *mmalloc(size_t size)
{
    if (!size)
        return NULL;

    /* if first_arena NULL, create arena */
    if (!first_arena){
        Arena *a = arena_alloc(size + sizeof(Arena) + sizeof(Header));
        if (!a)
            return NULL;
        arena_append(a);

        /* Create hdr */
        Header *hdr = (void *) a + sizeof(Arena);
        hdr_ctor(hdr, a->size - sizeof(Arena) - sizeof (Header));
        hdr = first_fit(size);

        if (hdr_should_split(hdr, size))
            (void) hdr_split(hdr, size);

        hdr->asize = size;
        void *p = (void *)hdr + sizeof(Header);

        /* everything OK return pointer to memory */
        return p;
    } else {
        /* create hdr */
        Header *hdr;
        hdr = first_fit(size);

        /* if theres no memory, alloc new arena for hdr */
        if(!hdr) { // TODO
            Arena *a = arena_alloc(size + sizeof(Arena) + sizeof(Header));
            if (!a)
                return NULL;
            arena_append(a);

            /* Create hdr of new arena */ //TODO maybe move to arena_alloc
            Header *hdr2 = (void *) a + sizeof(Arena);
            hdr_ctor(hdr2, a->size - sizeof(Arena) - sizeof (Header));
            Header *first = (void *) first_arena + sizeof(Arena);
            Header *last;
            if (first->next)
                last = hdr_get_prev(first);
            else
                last = first;
            last->next = hdr2;
            hdr2->next = first;

            /* now should be enough memory for hdr */
            hdr = first_fit(size);
            printf("HELOOOOOOOOOOOOOOOOOOOOOOOOO %p\n", hdr);
        }

        if (hdr_should_split(hdr, size))
            (void) hdr_split(hdr, size);
        //else
        //TODO
        hdr->asize = size;
        void *p = (void *)hdr + sizeof(Header);

        /* everything OK return pointer to memory */
        return p;
    }

    return NULL;
}

/**
 * Free memory block.
 * @param ptr       pointer to previously allocated data
 * @pre ptr != NULL
 */
void mfree(void *ptr)
{
    assert(ptr != NULL);

    Header *hdr = (void *) ptr - sizeof(Header);
    Header *prev = hdr_get_prev(hdr);
    Header *first = (void *) first_arena + sizeof(Arena);

    hdr->asize = 0;

    if (hdr_can_merge(hdr, hdr->next))
        hdr_merge(hdr, hdr->next);

    if ((hdr != first) && hdr_can_merge(prev, hdr))
        hdr_merge(prev, hdr);

    //if (prev == hdr)
    //    return;

    //prev->next = hdr->next;

    //if (first == hdr)
    //    first->
    //printf("jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj %p\n", prev);

}

/**
 * Reallocate previously allocated block.
 * @param ptr       pointer to previously allocated data
 * @param size      a new requested size. Size can be greater, equal, or less
 * then size of previously allocated block.
 * @return pointer to reallocated space or NULL if size equals to 0.
 */
void *mrealloc(void *ptr, size_t size)
{
    if (!size)
        return NULL;

    (void)ptr;
    (void)size;
    return NULL;
}
