#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/page.h"

#define DEBUG false

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

//helper reverse
void reverseHelper(char *begin, char *end);
void reverseFilename(char *s);

extern struct lock filesys_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */


tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  // printf("ENTERED PROCESS EXEC %s\n\n", file_name);
  //struct childThreadStatus *child;
  //struct thread *currentThread = thread_current(); 

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);  

  char *filenameCopy;
  filenameCopy = palloc_get_page (0);
  if (filenameCopy == NULL)
    return TID_ERROR;
  strlcpy (filenameCopy, file_name, strlen(file_name) + 1);

  char *firstArg = strtok_r (fn_copy, " ", &firstArg); //ADDED
  //palloc_free_page (fn_copy);

  // if (!(child = malloc(sizeof(struct childThreadStatus))))
  //   return TID_ERROR;
  
  // child->is_dead = false;
  // child->has_waited = false;
  // list_push_back(&currentThread->children, &child->elem);
  
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (firstArg, PRI_DEFAULT, start_process, filenameCopy); //CHANGED
  //palloc_free_page (filenameCopy);

  // if (tid == TID_ERROR) 
  //   return TID_ERROR;

  //printf("process execute : %d -> %d\n", thread_current()->tid, tid);
  

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  struct thread *child = thread_by_id (tid);
  
  if (!child) return -1;
  sema_down(&child->sema_exec);
  if (!child->has_loaded) return -1;
  
  
  // sema_down(&currentThread->sema_exec);
  // child->child_id = tid;
  // struct thread *t = get_thread_by_id (tid);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  //printf("ENTERED PROCESS START\n\n");
  struct thread *currentThread = thread_current();
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  //printf("FILENAME %s \n" , file_name);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (file_name, &if_.eip, &if_.esp);  
  palloc_free_page (file_name);

  if (!success) {
    currentThread->exit_status = -1;
    currentThread->has_loaded = false;
    // Failed, let parent process get exit status if needed
    sema_up (&currentThread->sema_exec);
    // sema_up (&currentThread->sema_wait);
    thread_exit ();
  } else { //Success!
    currentThread->has_loaded = true;
    sema_up (&currentThread->sema_exec);
  }
  
  // if (!success) { 
  //   currentThread->tid = -1;
  //   sema_up(&parent->sema_exec)
  //   thread_exit ();
  // }

  // sema_up(&parent->sema_exec);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{ 
  // printf("--process_wait : %d\n", child_tid);
  if (child_tid == -1) return -1;
  /* 
    > processes are not assigned to a new parent if their parent process exits before they do.
    > a process’s resources must be freed regardless of whether the child exits before or after
    its parent, whether that parent is waiting for it or not.
    > a process may wait for any given child at most once
    > regardless of how a process was terminated, either with a proper exit status or by the kernel
    the kernel must allow the parent to "find out what happened" to its child 
  */
  
  // struct list_elem *e = NULL;
  // struct childThreadStatus *child = NULL;
  struct thread *child = thread_by_id(child_tid);
  struct thread *currentThread = thread_current();
 
  if (!child || child->has_waited || currentThread->tid != child->parent_id) 
    return -1;
  if (child->has_exited) {
    sema_up(&child->sema_exit);
    return child->exit_status;
  }
    
  
  child->has_waited = true;
// printf("parent process wait before sema down: %d -> %d\n", thread_current()->tid, child_tid);
  sema_down(&child->sema_wait);
  // printf("parent process wait after sema down\n");
  int exit_status = child->exit_status;
  
  sema_up(&child->sema_exit);
  
  return exit_status;
  // struct list *children = &currentThread->children; 
  
  // //find child
  // if (!list_empty(children)) {
  //   for (e = list_front(children); e != list_end(children); e = list_next(e)) {
  //     child = list_entry(e, struct childThreadStatus, elem);
  //     if (child->child_id == child_tid)
  //       break;
  //     else child = NULL;
  //   }
  // }
 
  // //child not found or already waiting
  // if (!child || child->has_waited) return -1;
  // else child->has_waited = true;
  
  // if (!child->is_dead) {
  //   struct thread* childThread = get_thread_by_id(child_id);
  //   sema_down(&childThread->sema_wait);
  // }
  
  // int status = child->exit_status;
  
  // palloc_free_page(child);
  // list_remove(e);
  
  //return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  uint32_t *pd;
  // printf("exiting ------------------\n");
  struct thread *cur = thread_current ();
  // struct list *children = &cur->children;
  
  // while (!list_empty(children)) {
  //   struct list_elem *e = list_pop_front (children);
  //   struct childThreadStatus *child = list_entry(e, struct childThreadStatus, elem);
  //   if (child->is_dead)
  //     palloc_free_page(child);
  // }
  // for (struct list_elem *e = list_begin (&cur->children); e != list_end (&cur->children);) {
  //   struct thread *child = list_entry (e, struct thread, childelem);
  //   if (!child->has_exited) {
  //     child->parent_id = -42;
  //     e = list_next (&e);
  //     list_remove (&child->childelem);
  //   } else sema_up (&child->sema_exit);
  // }

  if (cur->exec) {
   // file_allow_write(cur->exec);
    lock_acquire(&filesys_lock);
    file_close(cur->exec);
    lock_release(&filesys_lock);
  }

  cur->has_exited = true;
  sema_up (&cur->sema_wait);
  if (cur->parent_id != -42) //TODO not null
    sema_down(&cur->sema_exit);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    } 
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */

bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
 
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *rest;
  rest = palloc_get_page (0);
  strlcpy (rest, file_name, PGSIZE); 
  
  /* Allocate and activate page directory. */
  hash_init (&t->page_table, page_hash, page_less, NULL);
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (t->name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
 
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  /* Set up stack. */
  if (!setup_stack (esp, rest))
    goto done; //never reaches success = true

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  file_deny_write(file); 
  t->exec = file;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // do not close file here postpone until termination
  //if (!success)
  //file_close(file);
  return success;
}

/* load() helpers. */


static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:
        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.
        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.
   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0); //points to starting address of a page
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);

      //wrap it into create_frame for palloc_get_page 
      //in order for it to be replaced
      //if kpage replaced -> fails

      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {

          //read file 


          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      //install page 
      if (!install_page (upage, kpage, writable)) 
        {
          //maps to page table upage and kpage and set writable or not 
          //lazy loading //structure is ame //but instead palloc_get_page you call create+page 
          //not frame -> physicsal adress //create page in virtual address space 
          //pass in argumnets saying where to bring back 
          //lazy loading whrn page fault in exception.c  
          //allocate frame on page demand 
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *file_name) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
         *esp = PHYS_BASE;
        char *token;
        char *rest = file_name;
        int argc = 0;
        int totalBytes = 0;
        char *address = 0;
        //int lengthCounter = 0;
        char* argAddresses[128];
          // 1. Parse the argument by white spaces
          // 2. Write each argument (including \0) in reverse
        reverseFilename(rest);

        while((token = strtok_r(rest, " ", &rest))) {
          argc++;
          *esp -= strlen(token) + 1;
          memcpy(*esp, token, strlen(token) + 1);
          argAddresses[argc-1] = *esp;
          totalBytes += strlen(token)+1;
        }

      // 3. Word align to 4 bytes, write the word align
        //cast to size_t % 4 to see how many
        int word_align = 4 - totalBytes % 4;
        *esp -= word_align;
        memset(*esp, 0, word_align);
        *esp -= sizeof(char) * 4;
        memset(*esp, 0, 4);

        for (int i = 0; i <= argc-1; i++) {
          *esp -= sizeof(char*);
          memcpy(*esp, &argAddresses[i], sizeof(char*));
        }

        address = *esp;
        *esp -= sizeof(char*);
        memcpy(*esp, &address, sizeof(char*));

        *esp -= sizeof(int);
        memcpy(*esp, &argc, sizeof(int));

        *esp -= sizeof(char) * 4;
        memset(*esp, 0, 4);

        //if (DEBUG) hex_dump((uintptr_t)*esp, *esp, PHYS_BASE - *esp, true);
      }
      else {
         palloc_free_page (kpage);
      }
       
    }
 

    //allocate chunk of memory users stack
    //after setup stack 
    //push everything in order with general steps 
    //General steps should be:
    // 4. Write four 0’s as last argument
    // 5. Write the addresses of each argument
    // 6. Write the address of argv
    // 7. Write argc
    // 8. Write a 0 for the return address
    // You’ll need to use a lot of memset and sizeof


  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/*
PROJECT 2 PART 1
support the feature of parsing the user program's filename and setup the stack correctly
~$bin/ls -l foo bar
argc = 4
argv[0] = /bin/ls
argv[1] = -l
argv[2] = foo
argv[3] = bar
FROM PHYS_BASE
argv[3]
argv[2]
...
*/

//Helper string reverse
void reverseFilename(char *s)
{
  char *begin = s;
  char *temp = s;
  while(*temp){
    temp++;
    if (*temp == '\0')
      reverseHelper(begin, temp-1);
    else if(*temp == ' '){
      reverseHelper(begin, temp-1);
      begin = temp+1;
    }
  }
  reverseHelper(s, temp-1);
}
 
void reverseHelper(char *begin, char *end)
{
  char temp;
  while (begin < end) {
    temp = *begin;
    *begin++ = *end;
    *end-- = temp;
  }
}