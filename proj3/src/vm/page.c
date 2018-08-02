#include "page.h"
#include "frame.h"
#include <stdio.h>
#include <string.h>

// Create a page that contains file. The page is not allocated and file is not loaded after this function call
struct page* create_file_page  (struct thread* t, void* uaddr, 
                                struct file* f, off_t ofs, 
                                size_t r_bytes, size_t z_bytes, bool writable) {
    
    struct page *p = malloc(sizeof(struct page));
    
    p->uaddr = uaddr;
    p->kaddr = NULL;
    p->flag = FILE;
    p->dirty = false;
    p->fptr = f;
    p->ofs = ofs;
    p->read_bytes = r_bytes;
    p->zero_bytes = z_bytes;
    p->writable = writable;
    
    if (hash_insert (&t->pages, &p->h_elem)) return NULL;
    return p;
}

//allocates and inserts into table, does not map frame yet
struct page* create_zero_page (struct thread* t, void* uaddr) {
    struct page *upage = malloc(sizeof(struct page));
    
    upage->uaddr = uaddr;
    upage->kaddr = NULL; 
    upage->flag = ZERO;
    upage->pinned = true;
    upage->dirty = false;
    upage->loaded = false;

    //if not null there was an entry in the hash table with that address
    if (hash_insert (&t->pages, &upage->h_elem))
        return NULL;

    return upage;
}

bool load_page (struct page* p) {
    if (!p) return false;
    if (p->loaded) return true;
    struct frame *f = create_frame(PAL_USER, p);
    if (!f) return false;
    if (p->flag == ZERO) memset(f->phys_addr, 0, PGSIZE);
    else {
        int read = file_read_at (p->fptr, f->phys_addr, p->read_bytes, p->ofs);
        if (read != (int)p->read_bytes) //if we read how many bytes we were supposed to
             return false;
        memset (f->phys_addr + read, 0, p->zero_bytes); //after those bytes were read, if there
        //are any zeroes we should keep writing, write them (to fit the page perfectly)
    }
    if (pagedir_set_page(thread_current()->pagedir, p->uaddr, f->phys_addr, true)) {
        pagedir_set_dirty (thread_current()->pagedir, f->phys_addr, false);
        p->kaddr = f->phys_addr;
        p->pinned = false;
        p->dirty = false;
        p->loaded = true;
        return true;
    }
    return false;
}

// Get the page from the current thread's supplementary page table by user virtual memory address, if not found return NULL
struct page* get_page_by_uaddr(void* addr) {
    // create a temporary page, just for lookup
    struct page *p = malloc(sizeof(struct page));
    p->uaddr = addr;
    struct hash_elem *e = hash_find (&thread_current()->pages, &p->h_elem);
    return e != NULL ? hash_entry (e, struct page, h_elem) : NULL;
}

// Returns a hash value for page p 
unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct page *p = hash_entry(elem, struct page, h_elem);
    return hash_bytes(&p->uaddr, sizeof p->uaddr);
}

// Returns true if page a precedes page b
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *a_ = hash_entry(a, struct page, h_elem);
    const struct page *b_ = hash_entry(b, struct page, h_elem);
    return a_->uaddr < b_->uaddr;
}
