#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "swap.h"

static struct block *swap_block;
static struct bitmap *swap_table;

static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

// the number of possible (swapped) pages.
static size_t swap_size;

void swap_init (void) {
  swap_block = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_table = bitmap_create(swap_size);
  bitmap_set_all(swap_table, true);
}

/* write data in a page to 8 sectors in swap block...swap out 
Since one sector is 512 bytes, and one page is 4KB, it means it takes 8 sectors to store one page.
In the bitmap, we want to find 8 consecutive bits, corresponding to 8 consecutive sectors in disk,
to use as the index to the disk
*/
size_t swap_to_block (void *uaddr) {

}


/* read data from 8 consecutive sectors to a page...swap in */
void read_to_page (void *uaddr, size_t start) {
  
}

void swap_free (size_t start) {
  
}

/* 
Bitmaps are essentially an array of booleans. This is very useful in project 3 to keep track of which
sectors on disk, organized contiguously from sector 0 to sector n, are free and which sectors are
not. By iterating through the bits and finding the first free bit, it allows for an easy "first fit" policy
for cache eviction */


/* sets the boolean at index <idx> to the value <bool> */
//void bitmap_set (struct bitmap *, size_t idx, bool);
/* sets the boolean at index <idx> to the true */
//void bitmap_mark (struct bitmap *, size_t idx);
/* sets the boolean at index <idx> to the false */
//void bitmap_reset (struct bitmap *, size_t idx);
/* beginning from index <start>, finds the first instance of <cnt> consecutive
<bool> bits and returns the index */
//size_t bitmap_scan (const struct bitmap *, size_t start, size_t cnt, bool);
/* same as bitmap_scan, but in addition also flips the bits */
//size_t bitmap_scan_and_flip (struct bitmap *, size_t start, size_t cnt, bool);
//void bitmap_destroy (struct bitmap *);