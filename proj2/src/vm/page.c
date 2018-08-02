#include "page.h"

void page_init(void) {

}

struct page* find_page(void* uaddr) {
    return NULL;
}

// Create a page that contains file. The page is not allocated and file is not loaded after this function call
struct page* create_file_page   (struct thread* t, void* uaddr, 
                                struct file* f, off_t ofs, 
                                size_t r_bytes, size_t z_bytes, bool writable) {

    return NULL;
}
/*
malloc(page); //initialize all member variables inside the page
*/

// Create a page that contains all zeroes. The page is allocated and mapped to a frame after this function call
struct page* create_zero_page   (struct thread* t, void* uaddr) {
    return NULL;
}
/*
page->page_flag = zero
create swap page 
*/

// Remove a page from the current thread's supplementary 
void remove_page(struct page* p) {

}
/*
find the page, go to frame table, deallocate the frame associated with this page
free(page)
if it is a file page, close the file 
if file is writable, wite back the file to disk
*/

// Write the frame to the file that page is loaded from
bool write_to_file(struct page* p) {
    return false;
}

// Unmap all mapping for the current thread
void clear_mapping(void) {

}

// Free all pages for the current thread
void free_all_pages(void) {

}

// Allocate and map the page to a frame. How data is loaded is determined by page's flag
bool load_page (struct page* p) {
    return false;
}
/*
loading -> create frame() -> paddr -> page.kaddr 
*/

// Unlink a page with its mapped frame
bool unload_page(struct page* p) {
    return false;
}
/*
remove_frame(page->associated frame)
load = false
*/

// Grow the user stack by a page with zeroes
struct page* stack_growth(struct thread* t, void* uaddr, bool user) {
    return NULL;
}

void clear_all_kernelpin(void) {

}

// Get the page from the current thread's supplementary page table by user virtual memory address, if not found return NULL
struct page* get_page_by_uaddr(void* addr) {
    return NULL;
}

// Get the page from the current thread's supplementary page table by mapid_t, if not found return NULL
struct page* get_page_by_mapid(mapid_t mapid) {
    return NULL;
}

void add_mentry(struct mentry* m) {

}

void remove_mentry(mapid_t mapid) {

}

// Returns a hash value for page p 
unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED) {
    struct page *a = hash_entry(elem, struct page, h_elem);
    return hash_int((int)a->uaddr);
}

// Returns true if page a precedes page b
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct page *a_ = hash_entry(a, struct page, h_elem);
    struct page *b_ = hash_entry(b, struct page, h_elem);

    return a_->uaddr < b_->uaddr;
}
