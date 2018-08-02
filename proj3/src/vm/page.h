#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <stdio.h>
#include "threads/thread.h"
#include "filesys/file.h"

typedef int mapid_t;

enum page_flag {
    FILE,
    ZERO,
    SWAP
};

struct mentry {
    mapid_t mapid;
    size_t size; 
    void *start;
    struct file* file;
    struct list_elem elem;
};

struct page {
    void* kaddr; /* Mapped kernel (physical) address of the frame. */
    void* uaddr; /* User virtual address of the page */
    
    bool loaded; /* If the page is allocated and mapped to a frame */
    enum page_flag flag; /* Flag of how this page should be loaded */

    struct file *fptr; /* File that waited to be loaded to the page */
    off_t ofs;         /* Offset of where to start loading the file */
    size_t read_bytes; /* How many bytes needed to be read */
    size_t zero_bytes; /* How many bytes needed to be zeroed out */
    bool writable; /* If the file is read-only and read-and-write */

    mapid_t pmapid; /* Identifier for mapped file */
    size_t swap_id; /* Swap block sector id. */
    
    // Pinned is set to true if kernel code is currently accessing the page table entry
    bool pinned;
    bool dirty;

    struct hash_elem h_elem; /* Hash element for thread's supplementary page table. */  
};


// Create a page that contains file. The page is not allocated and file is not loaded after this function call
struct page* create_file_page   (struct thread* t, void* uaddr, 
                                struct file* f, off_t ofs, 
                                size_t r_bytes, size_t z_bytes, bool writable);

// Create a page that contains all zeroes. The page is allocated and mapped to a frame after this function call
struct page* create_zero_page   (struct thread* t, void* uaddr);

struct page* get_page_by_uaddr(void* addr);

// Allocate and map the page to a frame. How data is loaded is determined by page's flag
bool load_page (struct page* p);

// Returns a hash value for page p 
unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED);

// Returns true if page a precedes page b
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif
