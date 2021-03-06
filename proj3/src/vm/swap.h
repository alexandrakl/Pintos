#ifndef SWAP_H
#define SWAP_H

#include <stdbool.h>
#include <stdio.h>

/* initialize swap table */
void swap_init(void);

/* write data in a page to 8 sectors in swap block */
size_t swap_to_block(void* uaddr);

/* read data from 8 consecutive sectors to a page */
void read_to_page(void* uaddr, size_t start);

void vm_swap_free (size_t swap_index);

#endif