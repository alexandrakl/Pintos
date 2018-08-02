#ifndef FRAME_H
#define FRAME_H

#include <hash.h> 
#include "threads/palloc.h"
#include "vm/page.h"

// The lock on the global frame table
struct lock frame_table_lock;

// The global frame table which indicates physical memory slots
struct list frame_table;

struct frame {
    void* phys_addr;            /* physical address of the frame */
    struct page* paired_page;   /* paired page struct of the frame */ 
    struct hash_elem h_elem;    /* hash element for frame table */

    int idle_elapse;            /* track the time since the current frame is idle */
    bool load_pin;
};

void frame_table_init(void); // initialize the frame table

// Allocate a frame from the pool for the given page
struct frame* create_frame(enum palloc_flags flags, struct page* pair_pg);
/*
malloc(new frame)
hash_insert(new frame)
palloc_get_page(1 page) = phys_addr
new frame->phys_addr = phys_addr
new frame->page_pg = pg
*/

// Deallocate a frame and unmap its paired_page after writing data stored in addr to disk
void free_frame(void* addr);
/*
hash_find(frame_table, addr)
free(frame)
create_frame()
*/

// Responsible for the entire eviction process
void frame_eviction(void);
/*
create_frame() 
*/

// Update idle_elapse for all frames
void frame_table_tick(void);

#endif 