#ifndef FRAME_H
#define FRAME_H

#include <stdio.h>
#include <hash.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "vm/page.h"

// The lock on the global frame table
struct lock frame_table_lock;
struct hash frame_table;

struct frame {
    void* phys_addr;            /* physical address of the frame */
    struct page* paired_page;   /* paired page struct of the frame */ 
    struct hash_elem h_elem;    /* hash element for frame table */
    struct thread* owner;       /* The thread that owns the frame */
};

void frame_table_init(void); // initialize the frame table

// Allocate a frame from the pool for the given page
struct frame* create_frame(enum palloc_flags flags, struct page* pair_pg);

// Returns a hash value for page p 
unsigned frame_hash(const struct hash_elem *elem, void *aux UNUSED);
// Returns true if page a precedes page b
bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);


#endif 