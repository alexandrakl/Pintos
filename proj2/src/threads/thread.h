#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include "debug.h"
#include "list.h"
#include <stdint.h>
#include "threads/synch.h"
#include <hash.h>

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */


/* A kernel thread or user process.
   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:
        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+
   The upshot of this is twofold:
      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.
      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.
   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
#endif

    //ADDED ALEXA
    int64_t ticks;                        /* Number of ticks when each thread needs to wake up */
    int initial_priority;                 /* Initial priority before priority donation happens*/
    bool update;                          /* If priority donation has occurred */
    struct list acquired_locks_list;      /* All locks a thread has acquired */
    struct lock *wanted;                  /* Lock that the thread wants */
   
    struct file *exec; 
    tid_t parent_id;
    int exit_status;
    bool has_loaded;
    bool has_waited;
    bool has_exited;
    struct list children;
    struct list_elem childelem;
    struct semaphore sema_exec;
    struct semaphore sema_wait;
    struct semaphore sema_exit; 

    struct hash page_table;  

    /* Owned by thread.c. */
    // Don't add any variables below this value
    unsigned magic;                     /* Detects stack overflow. */
  };

//user program and kernel //exit code = 100
//parent process wait for child process 
//needs some communiccation 
//in process exit some way to deliveer exit code to parent 
// child thread might be completely gone
//simple implementation is keeping a list of child statuses 
//when cgildren exit stores all the infomarion in the parent struct 
//retrieve from parent's list does not only contain child's pointer
//childstatus struct that contains thread pointer(tid), exit status code, whether has been waitin, has_dead 
//because parent can only wait for child once 
//if the child is dead still in the list 
//all info kpet inside parent's thread
// struct childThreadStatus {
//   struct list_elem elem;
//   int exit_status;
//   bool has_waited;
//   tid_t child_id;
//   bool is_dead;
// };
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

//ADDED START
bool list_less_comp (const struct list_elem* a, 
                    const struct list_elem* b, void* aux);

bool list_priority_comp (const struct list_elem* a, 
                    const struct list_elem* b, void* aux); 

void updatePriority (struct thread *t, int new_priority);

//ADDED END

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

struct thread* thread_by_id(tid_t tid);

#endif /* threads/thread.h */