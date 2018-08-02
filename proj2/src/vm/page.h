#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/syscall.h"

enum page_flag
{
    FILE,
    ZERO,
    SWAP
};

struct mentry
{
    mapid_t mapid;
    struct list_elem elem;
};

struct page 
{
    void* kaddr; /* Mapped kernel (physical) address of the frame. */
    void* uaddr; /* User virtual address of the page */
    struct thread* owner; /* The thread that owns the page */
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

    struct hash_elem h_elem; /* Hash element for thread's supplementary page table. */  
};

void page_init(void);

struct page* find_page(void* uaddr);

// Create a page that contains file. The page is not allocated and file is not loaded after this function call
struct page* create_file_page   (struct thread* t, void* uaddr, 
                                struct file* f, off_t ofs, 
                                size_t r_bytes, size_t z_bytes, bool writable);
/*
malloc(page); //initialize all member variables inside the page
*/

// Create a page that contains all zeroes. The page is allocated and mapped to a frame after this function call
struct page* create_zero_page   (struct thread* t, void* uaddr);
/*
page->page_flag = zero
create swap page 
*/

// Remove a page from the current thread's supplementary 
void remove_page(struct page* p);
/*
find the page, go to frame table, deallocate the frame associated with this page
free(page)
if it is a file page, close the file 
if file is writable, wite back the file to disk
*/

// Write the frame to the file that page is loaded from
bool write_to_file(struct page* p);

// Unmap all mapping for the current thread
void clear_mapping(void);

// Free all pages for the current thread
void free_all_pages(void);

// Allocate and map the page to a frame. How data is loaded is determined by page's flag
bool load_page (struct page* p);
/*
loading -> create frame() -> paddr -> page.kaddr 
*/

// Unlink a page with its mapped frame
bool unload_page(struct page* p);
/*
remove_frame(page->associated frame)
load = false
*/

// Grow the user stack by a page with zeroes
struct page* stack_growth(struct thread* t, void* uaddr, bool user);

void clear_all_kernelpin(void);

// Get the page from the current thread's supplementary page table by user virtual memory address, if not found return NULL
struct page* get_page_by_uaddr(void* addr);

// Get the page from the current thread's supplementary page table by mapid_t, if not found return NULL
struct page* get_page_by_mapid(mapid_t mapid);

void add_mentry(struct mentry* m);
void remove_mentry(mapid_t mapid);

// Returns a hash value for page p 
unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED);

// Returns true if page a precedes page b
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif
