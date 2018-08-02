#include "frame.h"

// The global frame table which indicates physical memory slots
void frame_table_init(void) {
    lock_init (&frame_table_lock);
    hash_init (&frame_table, frame_hash, frame_less, NULL);
}

// Allocate a frame from the pool for the given page
struct frame* create_frame(enum palloc_flags flags, struct page* pair_pg) {
    lock_acquire (&frame_table_lock);
    void *frame_page = palloc_get_page (flags);
    
    //TODO: any frame from any thread
    if (frame_page == NULL) {
        printf("NOT YET\n");
    }

    struct frame *f = malloc(sizeof(struct frame));
    if (!f) {
        lock_release(&frame_table_lock);
        return NULL;
    }
    
    f->owner = thread_current();
    f->phys_addr = frame_page;
    f->paired_page = pair_pg;

    hash_insert(&frame_table, &f->h_elem);
    
    lock_release(&frame_table_lock);
    return f;
}

// Returns a hash value for page p 
unsigned frame_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct frame *f = hash_entry(elem, struct frame, h_elem);
    return hash_bytes(&f->phys_addr, sizeof f->phys_addr);
}

// Returns true if page a precedes page b
bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct frame *a_ = hash_entry(a, struct frame, h_elem);
    const struct frame *b_ = hash_entry(b, struct frame, h_elem);
    return a_->phys_addr < b_->phys_addr;
}

