#ifndef SWAP_H
#define SWAP_H

#include <stdbool.h>

/* initialize frame table */
void swap_init(void);

/* write data in a page to 8 sectors in swap block */
size_t swap_to_block(void* uaddr);

/* read data from 8 consecutive sectors to a page */
bool read_to_page(void* uaddr, size_t start);

#endif