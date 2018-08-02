#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "vm/page.h"
void syscall_init (void);
void exit(int status);
bool my_munmap(mapid_t mid);
#endif 