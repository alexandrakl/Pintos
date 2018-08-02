#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/string.h"
#include "threads/malloc.h"

#include "vm/frame.h"
#include "vm/swap.h"


#define DEBUG false

static void syscall_handler (struct intr_frame *);
bool is_bad_ptr (void* ptr); 
int write(int fd, const void* buffer, unsigned size);
tid_t exec(const char* file);
int wait(tid_t pid);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int read(int fd, void* buffer, unsigned size);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void halt(void);

mapid_t my_mmap(int fd, void *);

struct list files_opened;
struct list files_closed;
struct lock filesys_lock;
//int globalCount = 2;

struct FDToFile {
  int fd;
  struct file* filePtr;
  struct list_elem elem;
  char* fileName;
  tid_t owner;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&files_opened);
  list_init(&files_closed);
  lock_init (&filesys_lock);
}

bool is_bad_ptr (void* ptr) 
{
  if (ptr == NULL || !is_user_vaddr(ptr) /* || pagedir_get_page(thread_current()->pagedir, ptr) == NULL */) {
    if (lock_held_by_current_thread(&filesys_lock))
      lock_release (&filesys_lock);
    return true; //is bad ptr
  }
  return false; //is good ptr

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //first check if f->esp is a valid pointer)
  if ( is_bad_ptr(f->esp) == true)
  {
    exit(-1);
  }

/*
This integer pointer is now pointing to the contents of the actual buffer we need. If we
directly cast this int* into a void*, you will be getting the address of the buffer, not the
buffer itself, therefor we need to dereference the int* in order to get the contents, then cast
it into a void*
int* ptr = (int*)f->esp + 2;
void* buffer = (void*)*ptr;

*/
    thread_current()->esp = f->esp;
    // printf("ENTERED SYSCALL\n\n");
    switch(*(int*)f->esp)
    {
    case SYS_WRITE: //SYS_WRITE, /* Write to a file. */
      {
        if (is_bad_ptr((int*)f->esp + 1) 
        || is_bad_ptr((int*)f->esp + 2) 
        || is_bad_ptr((unsigned*)f->esp + 3)) exit(-1);
        // printf("sdfgsergserg\n");
        int fd = *((int*)f->esp + 1);
        // printf("sdfgsergserg\n");
        void* buffer = (void*)(*((int*)f->esp + 2));
        // printf("sdfgsergserg\n");
        unsigned size = *((unsigned*)f->esp + 3);
        //run the syscall, a function of your own making
        //since this syscall returns a value, the return value should be
        //stored in f->eax
        // printf("SIZE: %d\n", size);
        int writeReturn = write(fd, buffer, size);
        f->eax = writeReturn;
        // printf("f->eax: %d\n", f->eax);
        break;
      }
      case SYS_EXIT: /* Terminate this process. */
      {
        // printf("please help me!: %d\n", thread_current()->tid);
        if ( is_bad_ptr((int*)f->esp + 1) ) 
          exit(-1);
        int statusProcess = *((int*)f->esp + 1);
        //printf("STATUES PROCESS %d  \n", statusProcess);
        if (statusProcess < 0)
          exit (-1);
        else
          exit(statusProcess);
      }
      case SYS_HALT: /* Halt the operating system. */
      {
        halt();
        break;
      }
      case SYS_EXEC: /* Start another process. */ 
      {
        if (is_bad_ptr((char **)(f->esp + 4)))
        { 
          exit(-1);
          } 
        char *file = *(char **)(f->esp + 4);
        tid_t id = exec(file);
        f->eax = id;
        // printf("--SYS_EXEC %s %d\n", file, id);
        break;
      }

      case SYS_WAIT: /* Wait for a child process to die. */
      {

        // if(*((int*)f->esp + 4) == NULL) {
        //   exit(-1);
        // }
        if (is_bad_ptr((char **)(f->esp + 1))) exit(-1);
        int pid = *((int *)f->esp + 1);
        // printf("wait for %d\n", pid);
        int waitReturn = wait(pid);
        f->eax = waitReturn;
        break;
      }
      case SYS_CREATE: /* Create a file. */ 
      { 

        if(DEBUG) printf("1\n");
        if(*(char **)(f->esp + 4) == NULL ||
           *(int *)(f->esp + 8) < 0) {
          if(DEBUG) printf("2\n"); 
          exit(-1);
        }

        if(DEBUG) printf("3\n");

        char *file = *(char **)(f->esp + 4);
        if(DEBUG) printf("4\n");
        unsigned initial_size = *(int *)(f->esp + 8);
        if(DEBUG) printf("5\n");
        if(DEBUG) printf("INITIAL_SIZE: %d\n", initial_size);
        int createReturn = create(file, initial_size);
        f->eax = createReturn;
        if(DEBUG) printf("6\n");
        break;
      }
      case SYS_REMOVE: /* Delete a file. */ 
      {
        if (is_bad_ptr((char **)(f->esp + 4))) exit(-1); 
        char* file = *(char **)(f->esp + 4);
        remove(file);
        break;
      }
      case SYS_OPEN: /* Open a file. */ 
      {
        if (is_bad_ptr((char **)(f->esp + 4))) exit(-1);
        char *file = *(char **)(f->esp + 4);
        // printf("-------------------- %s\n", file);
        int openReturn = open(file);
        f->eax = openReturn;
        break;
      }
      case SYS_FILESIZE: /* Obtain a file’s size. */
      {
        //printf("FILZE\n");
        if (is_bad_ptr((int*)f->esp + 1)) exit(-1);
        int fd = *((int*)f->esp + 1); //given file descriptor what is the file 
        int fileSize = filesize(fd);
        f->eax = fileSize;
        //printf("FILZE %d\n", fileSize);
        break;
      }
      case SYS_READ: /* Read from a file. */
      {
        if (is_bad_ptr((int*)f->esp + 1)) exit(-1);
        if (is_bad_ptr((int*)f->esp + 2)) exit(-1);
        if (is_bad_ptr((int*)f->esp + 3)) exit(-1);
        int fd = *((int*)f->esp + 1);
        void* buffer = (void*)(*((int*)f->esp + 2));
        unsigned size = *((unsigned*)f->esp + 3);
        int readReturn = read(fd, buffer, size);
        f->eax = readReturn;
        // printf("f->eax: %d\n", f->eax);
        break;
      }
      case SYS_SEEK: /* Change position in a file. */
      {
        if (is_bad_ptr((int*)f->esp + 1)) exit(-1);
        if (is_bad_ptr((int*)f->esp + 2)) exit(-1);

        seek(*((int*)f->esp + 1), *((int*)f->esp + 2));
        break;
      }
      case SYS_TELL: /* Report current position in a file. */
      {
        if (is_bad_ptr((int*)f->esp + 1)) exit(-1);
        int fd = *((int*)f->esp + 1);
        f->eax = tell(fd);
        break;
      }
      case SYS_CLOSE: /* Close a file. */
      {
        if (is_bad_ptr((int*)f->esp + 1)) exit(-1);
        int fd = *((int*)f->esp + 1);
        close(fd);
        break;
      }

      case SYS_MMAP:
      {
        int fd = *((int*)f->esp + 1);
        void* buffer = (void*)(*((int*)f->esp + 2));
       // printf("Test 00SY\n");
        f->eax = my_mmap (fd, buffer);
        break;
      }

      case SYS_MUNMAP:
      {
        mapid_t mapid = *((int*)f->esp + 1);
        my_munmap(mapid);
        break;
      }
    
      default:
        break;
    }
    // printf("end syscall\n");
}

void close(int fd) {
  //printf("\nSTART CLOSE \n");
  lock_acquire (&filesys_lock);
  //printf ("Printing file fd inside CLOSE %d \n",fd);
  //struct FDToFile *tempFileDesc;
  // struct list_elem *e2;
  // e2 = list_head(&files_closed);

  // // Seeing if file has been previously closed
  // while((e2 = list_next(e2)) != list_end(&files_closed)) {
  //   tempFileDesc = list_entry(e2, struct FDToFile, elem);
  //   if(tempFileDesc->fd == fd) {
  //     exit(-1);
  //   }
  // }
  struct FDToFile *fileDesc;
  struct list_elem *e;
  e = list_head(&files_opened);
  // Seeing if file that is trying to be closed is open in the first place
  while ((e = list_next(e)) != list_end(&files_opened)) {
    fileDesc = list_entry(e, struct FDToFile, elem);
    if (fileDesc->fd == fd && fileDesc->owner == thread_current()->tid) {
      //list_insert(list_begin(&files_closed), &fileDesc->elem);
      file_close(fileDesc->filePtr);
      list_remove(e);
      free(fileDesc);
      lock_release (&filesys_lock);
      return; // Nothing else to do, no need to keep looping
    }
  }

  //printf("\nSTART CLOSE \n");
  lock_release (&filesys_lock);
}

unsigned tell(int fd) {
  lock_acquire (&filesys_lock);
  struct FDToFile *fileDesc = NULL;

  struct list_elem *e = list_head(&files_opened);
  
  while((e = list_next(e)) != list_end(&files_opened)) {
    fileDesc = list_entry(e, struct FDToFile, elem);
    if (fileDesc->fd == fd && fileDesc->owner == thread_current()->tid)
      break;
  }
  unsigned ret;
  if (fileDesc && fileDesc->filePtr)
    ret = file_tell(fileDesc->filePtr);
  else
    ret = -1; // TODO need sys_exit?

  lock_release (&filesys_lock);
  return ret;
}

void seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct FDToFile *fileDesc = NULL;

  struct list_elem *e = list_head(&files_opened);
  
  while ((e = list_next(e)) != list_end(&files_opened)) {
    fileDesc = list_entry(e, struct FDToFile, elem);
    if (fileDesc->fd == fd && fileDesc->owner == thread_current()->tid)
      break;
  }
  if (fileDesc && fileDesc->filePtr)
    file_seek(fileDesc->filePtr, position);
  else {
    lock_release (&filesys_lock);  
    return; // TODO need sys_exit?
  }
  lock_release (&filesys_lock);
}

int read(int fd, void* buffer, unsigned size) {
  // printf("FD %d\n", fd);
  // printf("size: %d\n", size);
  if(is_bad_ptr(buffer) == true) exit(-1); // not needed for project 3

  lock_acquire (&filesys_lock);
  
  struct FDToFile *fileDesc;

  struct list_elem *e;

  e = list_head(&files_opened);

  if(fd == 0) { // STDIN 
    uint8_t* tempBuf = buffer;
    for(unsigned int i = 0; i < size; i++)
      tempBuf[i] = input_getc();
    lock_release (&filesys_lock);
    return size;
  } 
  else if (fd == 1) { // STDOUT
    lock_release (&filesys_lock);
    return -1;
  } 
  else
    while((e = list_next(e)) != list_end(&files_opened)) {
      fileDesc = list_entry(e, struct FDToFile, elem);
      if (fileDesc->fd == fd) {
        // printf("FILEDESCRP MATCH\n");
        // if (is_bad_ptr(fileDesc->filePtr) == true) { exit(-1); }
        // printf("BEFORE FILE_READ\n");
        // printf("FILE: %s\n", fileDesc->fileName);
        int tempFileRead = file_read(fileDesc->filePtr, buffer, size);
        // printf("tempFileRead %d\n", tempFileRead);  
        lock_release (&filesys_lock);
        return tempFileRead;
      }
    } 

  lock_release (&filesys_lock);
  return -1;
}


//Returns the size, in bytes, of the file open as fd.
int filesize(int fd) {
// printf ("Printing file fd inside filesize %d \n",fd);
  //look through your list 
  //find the file specific to your fd 
  //create file struct
  //pass it in file_length

 // struct file* 
  //off_t file_length (struct file *);
// printf("aergaergerg\n");
  lock_acquire (&filesys_lock);
  struct FDToFile *fileDesc;

  struct list_elem *e = list_head(&files_opened);

  while ((e = list_next(e)) != list_end(&files_opened)) {
    fileDesc = list_entry(e, struct FDToFile, elem);
    if (fileDesc->fd == fd) {
      // int fileLength = file_length(fileDesc->filePtr);
      // printf("FILE_LENGTH: %d\n", fileLength);
      //  printf("Fileptr inside filesize %d \n", fileDesc->filePtr ); 
      int size = file_length(fileDesc->filePtr);
      //  printf("size : %d", size);
      lock_release (&filesys_lock);
      return size;
    }
  }
  lock_release (&filesys_lock);
  return -1;
}


int open(const char* file) {
 
  int count = 1;
  // printf("FILE_OPEN: %s\n", file);
  if (is_bad_ptr(file) == true) { exit(-1); }
  
  struct FDToFile *tempFileDesc;
  struct list_elem *e;
  e = list_head(&files_opened);

// int max_count = 0;
  while ((e = list_next(e)) != list_end(&files_opened)) {
    tempFileDesc = list_entry(e, struct FDToFile, elem);
    // if(strcmp(tempFileDesc->fileName, file) == 0) {
    //   // printf("STRCMP\n");
    //   int currFd = tempFileDesc->fd;
    //   // printf("currFd: %d\n", currFd);
    //   currFd += 1;
    //   tempFileDesc->fd = currFd;
    //   // printf("returned fd: %d\n", currFd);
    //   return currFd;
    // }
    // else {
      //count of last element
      // count = tempFileDesc->fd;
      // printf("INSIDE WHILE COUNT %d \n", count);
      count = count < tempFileDesc->fd ? tempFileDesc->fd : count;
    // }

  }

  lock_acquire (&filesys_lock);

  struct file* filePtr = filesys_open(file); 
  if(filePtr != NULL) {
     struct FDToFile* fileDesc = calloc(1, sizeof *fileDesc);
    // printf("FILEPTR != NULL\n");
    // printf("FILE_DESC->FD_before: %d\n", count);
    fileDesc->fd = ++count;
    // printf("FILE_DESC->FD_after INSIDE OPEN: %d\n", fileDesc->fd);
    fileDesc->filePtr = filePtr;
    // printf("Fileptr inside open %p \n", filePtr );
    fileDesc->fileName = file;
    fileDesc->owner = thread_current()->tid;
    list_insert(list_begin(&files_opened), &fileDesc->elem);
    // printf("RETURN FD: %d\n", fileDesc->fd);
    lock_release (&filesys_lock);
    return fileDesc->fd;
  }
  lock_release (&filesys_lock);
  return -1;  
}

// Deletes the file called file. Returns true if successful, false otherwise. A file may be
// removed regardless of whether it is open or closed, and removing an open file does not close
// it. See Removing an Open File, for details.
bool remove(const char* file) {
  if (is_bad_ptr(file) == true) { exit(-1); }
  // using synchronization constructs:
  lock_acquire (&filesys_lock);
  bool successful = filesys_remove(file);
  lock_release (&filesys_lock);
  
  return successful;
}

// Creates a new file called file initially initial_size bytes in size. Returns true if successful,
// false otherwise. Creating a new file does not open it: opening the new file is a separate
// operation which would require a open system call.
bool create(const char* file, unsigned initial_size) {

  //   check to see if valid file pointer
  if (is_bad_ptr(file) == true) { exit(-1); }
  // using synchronization constructs:
  lock_acquire (&filesys_lock);
  bool successful = filesys_create(file, initial_size);
  lock_release (&filesys_lock);
  if(DEBUG) printf("SUCCESSFUL: %d\n", successful);

  return successful;
}

// Runs the executable whose name is given in cmd_line, passing any given arguments, and
// returns the new process’s program ID (pid). Must return pid -1, which otherwise should
// not be a valid pid, if the program cannot load or run for any reason. Thus, the parent
// process cannot return from the exec until it knows whether the child process successfully
// loaded its executable. You must use appropriate synchronization to ensure this.
 tid_t exec(const char* file) {
  // printf("file_exec(): %s\n", file);
  if (is_bad_ptr(file) == true) { exit(-1); }
  // printf("TID: %d\n", process_execute(file));
  tid_t id = process_execute(file);

  return id;
 }

 int wait(tid_t pid) {
  // printf("wait()\n");
  // return pid;
  int id = process_wait(pid);
  return id;
 }

// Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). This
// should be seldom used, because you lose some information about possible deadlock situations,
// etc.
void halt(void) {
  shutdown_power_off();
}

int write(int fd, const void* buffer, unsigned size) { 
  if (is_bad_ptr(buffer) == true) { exit(-1); }
  lock_acquire (&filesys_lock);  
  struct FDToFile *fileDesc;

  struct list_elem *e = list_head(&files_opened);

  if (fd == 0) { // STDIN 
    // printf("FD == 0\n");
    // uint8_t* tempBuf = buffer;
    // for(int i = 0; i < size; i++) {
    //   tempBuf[i] = input_putc();
    // }
    lock_release (&filesys_lock);    
    return size;
  } else if (fd == 1) { // STDOUT
    // printf("FD == 1\n");
    putbuf(buffer, size);
    lock_release (&filesys_lock);    
    return size;
  } else {
    // printf("FD == 2\n");
    while ((e = list_next(e)) != list_end(&files_opened)) {
      fileDesc = list_entry(e, struct FDToFile, elem);
      if (fileDesc->fd == fd) {
        // printf("FILEDESCRP MATCH\n");
        struct page *p;
        void *upage = pg_round_down(buffer);
        while (upage < buffer + size) {
          p = get_page_by_uaddr(upage);
          load_page (p);
          if (p) p->pinned = true;
          upage += PGSIZE;
        }

        int tempFileWrite = file_write(fileDesc->filePtr, buffer, size);
        // printf("tempFileRead %d\n", tempFileRead);

        for (upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE) {
          p = get_page_by_uaddr(upage);
          if (p) p->pinned = false;
        }
        lock_release (&filesys_lock);    
        return tempFileWrite;
      }
    } 
  }
  
  lock_release (&filesys_lock);    
  return 0; 
}

// void exit(int status)
// Terminates the current user program, returning status to the kernel. If the process’s parent
// waits for it (see below), this is the status that will be returned. Conventionally, a status of 0
// indicates success and nonzero values indicate errors
void exit(int status) {
    // struct childThreadStatus *child = thread_current()->child;
    // if(child != NULL)
    //   child->exit_status = status;
    //printf("GOD PLEASE HELP ME FINISH THIS \n");
    // while (!list_empty (&files_opened))
    //   close (list_entry(list_back (&files_opened), struct FDToFile, elem)->fd);
     thread_current ()->exit_status = status;
     printf("%s: exit(%d)\n", thread_current()->name, status);
     thread_exit();
}

bool my_munmap(mapid_t mapid) {
  struct thread *t = thread_current();
  struct mentry *m = NULL;
  struct list_elem *e;

//get the memory mapped file entry if there
  if (!list_empty(&t->mmaps)){
    for (e = list_begin(&t->mmaps); e != list_end(&t->mmaps); e = list_next(e)) {
      struct mentry *tmp = list_entry(e, struct mentry, elem);
      if (tmp->mapid == mapid)
        m = tmp;
    }
  }

  if (m) {
    size_t fileSize = m->size;
    struct file *f = m->file;
    struct page *p = NULL;
    //loop through the adress space for file in increments of page size 
    for (size_t ofs = 0; ofs < fileSize; ofs += PGSIZE) {
      void *addr = m->start + ofs;
      size_t bytes = PGSIZE;
      if (PGSIZE + ofs >= fileSize)
        bytes = fileSize - ofs; 
      if ((p = get_page_by_uaddr(addr))) {    
        //if dirty then write back to file
        if (p->dirty 
        || pagedir_is_dirty(t->pagedir, p->kaddr) 
        || pagedir_is_dirty(t->pagedir, p->uaddr))   
          file_write_at (f, p->uaddr, bytes, ofs);
        pagedir_clear_page (t->pagedir, p->uaddr);  
        hash_delete(&t->pages, &p->h_elem); //delete from page table
      }
    }

    list_remove(&m->elem);
    free(m);
    return true;
  }
  return false;
}

mapid_t my_mmap(int fd, void *uaddr) {
  if (!uaddr || pg_ofs(uaddr) != 0 || fd <= 1)
       return -1;

  size_t fileSize;
  struct file *f = NULL;
  struct FDToFile *fileDesc;
  struct thread *t = thread_current();
  struct list_elem *e = list_head(&files_opened);

  while ((e = list_next(e)) != list_end(&files_opened)) {
    fileDesc = list_entry(e, struct FDToFile, elem);
    if (fileDesc->fd == fd) { //TODO: owner thread_current()? fileDesc->owner == t->tid
      if (fileDesc->filePtr)
        f = file_reopen(fileDesc->filePtr); //get the file to mmap
      break;
    }
  }

  if (f) {
    fileSize = file_length(f);
    if (fileSize == 0) { //if empty
      return -1;
    }
  } else { //if null 
    return -1;
  }
  
  size_t ofs;
  void *addr;
  //for loop in increments of page size
  for (ofs = 0; ofs < fileSize; ofs += PGSIZE) {
    addr = uaddr + ofs;
    if (get_page_by_uaddr(addr) || pagedir_get_page (t->pagedir, addr)) {
      return -1;
    }
  }

  for (ofs = 0; ofs < fileSize; ofs += PGSIZE) {
    addr = uaddr + ofs;
    size_t r_bytes;
    if (fileSize > PGSIZE + ofs)
      r_bytes = PGSIZE;
    else 
      r_bytes = fileSize - ofs;
    size_t z_bytes = PGSIZE - r_bytes;
    create_file_page(t, addr, f, ofs, r_bytes, z_bytes, true);
  }

  mapid_t mapid;
  if (list_empty(&t->mmaps))
    mapid = 1;
  else mapid = list_entry(list_back(&t->mmaps), struct mentry, elem)->mapid + 1;
  //the mapid is the last mapid used for the process plus one (same idea as file descriptors)
 
  struct mentry *m = malloc(sizeof(struct mentry));
  m->mapid = mapid;
  m->file = f;
  m->start = uaddr;
  m->size = fileSize;
  
  list_push_back (&t->mmaps, &m->elem);
  
  return mapid;
}

// Waits for a child process pid and retrieves the child’s exit status.
// If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
// If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
// wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes
// that have already terminated by the time the parent calls wait, but the kernel must
// still allow the parent to retrieve its child’s exit status, or learn that the child was terminated
// by the kernel.
// wait must fail and return -1 immediately if any of the following conditions is true:
// int wait(pid_t pid) {
//   return -1;
// }

//BAD WARNING = implicitit declaration of function
//            = incopatible type

//DEBUGGIN TIPS
//process_Wait -> parent waits for child to die and then keep going
//list of chilfren in thread struct needed for part 2
//parent reference in thresd struct
//semaphore eith initial value of 0 
//sema down 
//sema up

//inside thread_create set the pointer 

//2 sempahores : process wait and for the load function 
//child thread stsartprocess -> load 
//parent has to wait for child to load successfuly 
//exec return vslue check -> tid else -1 failed

//printf best way to DEBUGGIN
//before and after sema_down especially because context switching
//use a debug flag to turn on and off 
//process wait in parent process 
//suppose system freeze -> deadlock
//in sema up child thread may not sema up the parent thread -> wake her up
//another case is child thread is already dead 
//another: child thread doen't even run 
//print list of information about children 

//how to debug page fault?
//allows system to keep running
//kernel or user 
//kernel -> bug null pointer exception (have to deal bug in my code)
//user level -> test is doing smth bad  exit -1
//read or writer
//access or assign 
//memory management protection 
//each address mapping to memory
//not present - page is not in memory -- bit is invalid
//rigths violation - page is not allowed to be accesed/asigned by th process that requested
//ASSERT - useful for part 3 
//never delete them 
//ensures the correct behavior at the correfct stage
//in process wait child tid 
//part 3 very useful in synchronization 
//adding ASSERT and printf 
//using debug flag

//vsild if it is user level address and has a mapping to page table

// *eps = *void 
// ((*int)*eps) = 1
