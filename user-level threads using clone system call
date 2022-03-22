#define _GNU_SOURCE
#include <linux/futex.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * @brief Spin Lock object
 */
typedef struct {
    volatile int __lock;
    unsigned int __locker;
} spin_t;

/**
 * @brief Mutex object
 */
typedef struct {
    volatile int __lock;
    unsigned int __locker;
} mutex_t;

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#define gettid() syscall(SYS_gettid)

/**
 * @brief Initialize the spinlock object
 *
 * @param lock Spinlock object
 */
int spin_init(spin_t *lock)
{
    volatile int outval;
    volatile int *lockvar = &(lock->__lock);
    asm("movl $0x0,(%1);" : "=r"(outval) : "r"(lockvar));
    lock->__locker = 0;
    return 0;
}

/**
 * @brief Acquire a lock and wait atomically for the lock object
 *
 * @param lock Spinlock object
 */
int spin_acquire(spin_t *lock)
{
    int outval;
    volatile int *lockvar = &(lock->__lock);
    asm("whileloop:"
        "xchg   %%al, (%1);"
        "test   %%al,%%al;"
        "jne whileloop;"
        : "=r"(outval)
        : "r"(lockvar));
    return 0;
}

/**
 * @brief Release lock atomically
 *
 * @param lock Spinlock object
 */
int spin_release(spin_t *lock)
{
    int outval;
    volatile int *lockvar = &(lock->__lock);
    asm("movl $0x0,(%1);" : "=r"(outval) : "r"(lockvar));
    lock->__locker = 0;
    return 0;
}

/**
 * @brief Check if a lock has been acquired already
 *
 * @param lock Spinlock object
 */
int spin_trylock(spin_t *lock)
{
    return lock->__locker == 0 ? 0 : EBUSY;
}

/**
 * @brief Initialize the mutex lock object
 * @param lock Mutex Lock object
 */
int mutex_init(mutex_t *lock)
{
    volatile int *lockvar = &(lock->__lock);
    int outval;
    asm("movl $0x0,(%1);" : "=r"(outval) : "r"(lockvar));
    lock->__locker = 0;
    return 0;
}

/**
 * @brief Atomically acquire the lock and wait by sleeping if not available
 * @param lock Mutex Lock object
 */
int mutex_acquire(mutex_t *lock)
{
    volatile int outval;
    volatile int *lockvar = &(lock->__lock);
    asm("mutexloop:"
        "mov    $1, %%eax;"
        "xchg   %%al, (%%rdi);"
        "test %%al,%%al;"
        "je endlabel"
        : "=r"(outval)
        : "r"(lockvar));
    syscall(SYS_futex, lock, FUTEX_WAIT, 1, NULL, NULL, 0);
    asm("jmp mutexloop");
    asm("endlabel:");
    return 0;
}

/**
 * @brief Release the lock object atomically and wake up waiting threads
 * @param lock Mutex Lock object
 */
int mutex_release(mutex_t *lock)
{
    volatile int outval;
    volatile int *lockvar = &(lock->__lock);
    asm("movl $0x0,(%1);" : "=r"(outval) : "r"(lockvar));
    lock->__locker = 0;
    syscall(SYS_futex, lock, FUTEX_WAKE, 1, NULL, NULL, 0);
    return 0;
}

/**
 * @brief Check if a lock has been acquired already
 * @param lock Mutex object
 */
int mutex_trylock(mutex_t *lock)
{
    return lock->__locker == 0 ? 0 : EBUSY;
}

/**
 * @brief Default stack size for a thread
 */
#define STACK_SZ 65536

/**
 * @brief Default guard page size for a thread
 */
#define GUARD_SZ getpagesize()

/**
 * @brief Flags passed to clone system call in one-one implementation
 */
#define CLONE_FLAGS                                                    \
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | \
        CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
#define TGKILL 234

/**
 * @brief Thread Object
 */
typedef unsigned long thread;

/**
 * @brief Arguments passed to the wrapper function
 */
typedef struct funcargs {
    void (*f)(void *);
    void *arg;
    void *stack;
} funcargs;

/**
 * @brief Node in the TCB of the thread
 */
typedef struct node {
    unsigned long int tid;
    unsigned long int tidCpy;
    void *retVal;
    struct node *next;
    funcargs *fa;
} node;

/**
 * @brief Singly Linked List of TCBs
 */
typedef struct singlyLL {
    node *head;
    node *tail;
} singlyLL;

#define INIT_SIGNALS                 \
    sigset_t signalMask;             \
    sigfillset(&signalMask);         \
    sigdelset(&signalMask, SIGINT);  \
    sigdelset(&signalMask, SIGSTOP); \
    sigdelset(&signalMask, SIGCONT); \
    sigprocmask(SIG_BLOCK, &signalMask, NULL);

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/**
 * @brief Initialize the Singly Linked List
 * @param ll Pointer to a linked list object
 * @return 0 On sucess, -1 On failure -1
 */
int singlyLLInit(singlyLL *ll)
{
    if (!ll)
        return -1;
    ll->head = ll->tail = NULL;
    return 0;
}

/**
 * @brief Insert a node into the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the new node
 * @return On success Pointer to new node, On failure NULL
 */
node *singlyLLInsert(singlyLL *ll, unsigned long int tid)
{
    node *tmp;
    if (posix_memalign((void **) &tmp, 8, sizeof(node))) {
        perror("ll alloc");
        return NULL;
    }
    tmp->tid = tid;
    tmp->next = NULL;
    tmp->retVal = NULL;
    if (!ll->head) {
        ll->head = ll->tail = tmp;
    } else {
        ll->tail->next = tmp;
        ll->tail = tmp;
    }
    return tmp;
}

/**
 * @brief Delete a node from the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the node
 * @return On deletion 0, On not found -1
 */
int singlyLLDelete(singlyLL *ll, unsigned long int tid)
{
    node *tmp = ll->head;
    if (!tmp)
        return -1;
    if (tmp->tidCpy == tid) {
        ll->head = ll->head->next;
        if (tmp->fa && munmap(tmp->fa->stack, STACK_SZ + getpagesize()))
            return errno;
        free(tmp->fa);
        free(tmp);
        if (!ll->head)
            ll->tail = NULL;
        return 0;
    }
    while (tmp->next) {
        if (tmp->next->tidCpy == tid) {
            node *tmpNext = tmp->next->next;
            if (tmp->next == ll->tail)
                ll->tail = tmp;
            if (tmp->next->fa &&
                munmap(tmp->next->fa->stack, STACK_SZ + getpagesize()))
                return errno;
            free(tmp->next->fa);
            free(tmp->next);
            tmp->next = tmpNext;
            break;
        }
        tmp = tmp->next;
    }
    return 0;
}

/**
 * @brief Get the address of the tail node in the linked list
 * @param ll Pointer to the linked list
 * @return On sucess address of tail, On failure NULL
 */
unsigned long int *returnTailTidAddress(singlyLL *ll)
{
    if (!ll->head)
        return NULL;
    return &(ll->tail->tid);
}

/**
 * @brief Get the address of the node with a given tid
 *
 * @param ll Pointer to linked list
 * @param tid Thread ID of the node
 * @return On sucess address of tail, On failure NULL
 */
unsigned long int *returnCustomTidAddress(singlyLL *ll, unsigned long int tid)
{
    node *tmp = ll->head;
    while (tmp) {
        if (tmp->tidCpy == tid)
            return &(tmp->tid);
        tmp = tmp->next;
    }
    return NULL;
}

node *returnCustomNode(singlyLL *ll, unsigned long int tid)
{
    node *tmp = ll->head;
    while (tmp) {
        if (tmp->tidCpy == tid)
            return tmp;
        tmp = tmp->next;
    }
    return NULL;
}

/**
 * @brief Send process wide signal dispositions to all active threads
 * @param ll Pointer to linked list
 * @param signum Signal number
 * @return On success 0, On failure errno
 */
int killAllThreads(singlyLL *ll, int signum)
{
    node *tmp = ll->head;
    pid_t pid = getpid();
    int ret;
    pid_t delpid[100];
    int counter = 0;
    while (tmp) {
        if (tmp->tid == gettid()) {
            tmp = tmp->next;
            continue;
        }
        printf("Killed thread %ld\n", tmp->tid);
        ret = syscall(TGKILL, pid, tmp->tid, signum);
        if (ret == -1) {
            perror("tgkill");
            return errno;
        } else {
            if (signum == SIGINT || signum == SIGKILL)
                delpid[counter++] = tmp->tid;
        }
        tmp = tmp->next;
    }
    if (signum == SIGINT || signum == SIGKILL) {
        for (int i = 0; i < counter; i++)
            singlyLLDelete(ll, delpid[i]);
    }
    return 0;
}

/**
 * @brief Utility function to print the linked list
 * @param l Pointer to linked list
 */
void printAllNodes(singlyLL *l)
{
    node *tmp = l->head;
    while (tmp) {
        if (tmp->fa) {
            printf("tid%ld tidCpy%ld-->", tmp->tid, tmp->tidCpy);
            fflush(stdout);
        }
        tmp = tmp->next;
    }
    printf("\n");
    return;
}

/**
 * @brief Get the Return Value object
 * @param l Pointer to linked list
 * @param tid Thread ID of the node
 * @return On success address of return value, On failure NULL
 */
void *getReturnValue(singlyLL *l, unsigned long int tid)
{
    node *tmp = l->head;
    while (tmp) {
        if (tmp->tid == tid)
            return tmp->retVal;
        tmp = tmp->next;
    }
    return NULL;
}

/**
 * @brief Umbrella function to free resources used by threads
 * @param l Pointer to singlyLL list
 */
void deleteAllThreads(singlyLL *l)
{
    node *tmp = l->head;
    int *deleted = NULL;
    int numDeleted = 0;
    while (tmp) {
        if (tmp->tid == 0) {
            deleted = (int *) realloc(deleted, (++numDeleted) * sizeof(int));
            deleted[numDeleted - 1] = tmp->tidCpy;
        }
        tmp = tmp->next;
    }
    for (int i = 0; i < numDeleted; i++)
        singlyLLDelete(l, deleted[i]);
    free(deleted);
}

/**
 * @brief Thread object
 */
typedef unsigned long int thread;

#include <limits.h>

#define RED "\033[1;31m"
#define RESET "\033[0m"

/**
 * @brief Macro for installing custom signal handlers for threads
 */
#define WRAP_SIGNALS(signum)          \
    signal(signum, TLIB_SIG_HANDLER); \
    sigemptyset(&base_mask);          \
    sigaddset(&base_mask, signum);    \
    sigprocmask(SIG_UNBLOCK, &base_mask, NULL);

/**
 * @brief Custom signal handler function
 * @param signum Signal Number
 */
void TLIB_SIG_HANDLER(int signum)
{
    printf(RED "Signal Dispatched\n" RESET);
    printf("Thread tid %ld handled signal\n", (long) gettid());
    fflush(stdout);
}

spin_t __globalLock;
singlyLL __tidList;

/**
 * @brief Cleanup handler for freeing resources of all threads at exit
 */
void cleanup()
{
    deleteAllThreads(&__tidList);
    free(__tidList.head);
}

/**
 * @brief Library initialzer for setting up data structures and handlers
 */
static void init()
{
    spin_init(&__globalLock);
    INIT_SIGNALS
    singlyLLInit(&__tidList);
    node *insertedNode = singlyLLInsert(&__tidList, getpid());
    insertedNode->tidCpy = insertedNode->tid;
    insertedNode->fa = NULL;
    atexit(cleanup);
}

/**
 * @brief Function to allocate a stack to One One threads
 * @param size Size of stack excluding the guard size
 * @param guard Size of guard page
 */
static void *allocStack(size_t size, size_t guard)
{
    void *stack = NULL;
    // Align the memory to a 64 bit compatible page size and associate a guard
    // area for the stack
    stack = mmap(NULL, size + guard, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Stack Allocation");
        return NULL;
    }
    if (mprotect(stack, guard, PROT_NONE)) {
        munmap(stack, size + guard);
        perror("Stack Allocation");
        return NULL;
    }
    return stack;
}

void thread_exit(void *ret);

/**
 * @brief Wrapper for the routine passed to the thread
 * @param fa Function pointer of the routine passed to the thread
 */
static int wrap(void *fa)
{
    funcargs *temp = (funcargs *) fa;
    sigset_t base_mask;
    sigset_t maskArr[5];
    int sigArr[5] = {SIGTERM, SIGFPE, SIGSYS, SIGABRT, SIGPIPE};
    for (int i = 0; i < 5; i++) {
        base_mask = maskArr[i];
        WRAP_SIGNALS(sigArr[i]);
    }
    temp->f(temp->arg);
    thread_exit(NULL);
    return 0;
}

/**
 * @brief Create a One One mapped thread
 * @param t Reference to the thread
 * @param routine Function associated with the thread
 * @param arg Arguments to the routine
 */
int thread_create(thread *t, void *routine, void *arg)
{
    spin_acquire(&__globalLock);
    static int initState = 0;
    if (!t || !routine) {
        spin_release(&__globalLock);
        return EINVAL;
    }
    thread tid;
    void *thread_stack;
    if (initState == 0) {
        initState = 1;
        init();
    }
    node *insertedNode = singlyLLInsert(&__tidList, 0);
    if (!insertedNode) {
        printf("Thread address not found\n");
        spin_release(&__globalLock);
        return -1;
    }
    funcargs *fa;
    fa = (funcargs *) malloc(sizeof(funcargs));
    if (!fa) {
        printf("Malloc failed\n");
        spin_release(&__globalLock);
        return -1;
    }
    fa->f = routine;
    fa->arg = arg;
    thread_stack = allocStack(STACK_SZ, GUARD_SZ);
    if (!thread_stack) {
        perror("thread create");
        spin_release(&__globalLock);
        return errno;
    }
    fa->stack = thread_stack;
    tid = clone(wrap, thread_stack + STACK_SZ + GUARD_SZ, CLONE_FLAGS,
                (void *) fa, &(EXP1), NULL, &(EXP2));
    insertedNode->tidCpy = tid;
    insertedNode->fa = fa;

    if (tid == -1) {
        perror("thread create");
        free(thread_stack);
        spin_release(&__globalLock);
        return errno;
    }
    *t = tid;
    spin_release(&__globalLock);
    return 0;
}

/**
 * @brief Function to send signals to a specific thread
 * @param tid TID of the thread to which the signal has to be sent
 * @param signum Signal number of the signal to be sent to the thread
 */
int thread_kill(pid_t tid, int signum)
{
    if (signum == 0)
        return -1;
    int ret;
    node *insertedNode = returnCustomNode(&__tidList, tid);
    if (signum == SIGINT || signum == SIGCONT || signum == SIGSTOP) {
        killAllThreads(&__tidList, signum);
        pid_t pid = getpid();
        ret = syscall(TGKILL, pid, gettid(), signum);
        if (ret == -1) {
            perror("tgkill");
            return ret;
        }
        return ret;
    }
    if (insertedNode->tid == 0)
        return -1;
    pid_t pid = getpid();
    ret = syscall(TGKILL, pid, tid, signum);
    if (ret == -1) {
        perror("tgkill");
        return ret;
    }
    return ret;
}

/**
 * @brief Function to wait for a specific thread to terminate
 * @param t TID of the thread to wait for
 * @param guard Size of guard pag
 */
int thread_join(thread t, void **retLocation)
{
    spin_acquire(&__globalLock);
    void *addr = returnCustomTidAddress(&__tidList, t);
    if (!addr) {
        spin_release(&__globalLock);
        return ESRCH;
    }
    if (*((pid_t *) addr) == 0) {
        spin_release(&__globalLock);
        return EINVAL;
    }
    int ret;
    while (*((pid_t *) addr) == t) {
        spin_release(&__globalLock);
        ret = syscall(SYS_futex, addr, FUTEX_WAIT, t, NULL, NULL, 0);
        spin_acquire(&__globalLock);
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    if (retLocation) {
        node *insertedNode = returnCustomNode(&__tidList, t);
        *retLocation = insertedNode->retVal;
    }
    spin_release(&__globalLock);
    return ret;
}

/**
 * @brief Function to make a thread terminate itself
 * @param ret return value of the thread to be available to thread_join()
 * @note Implicit call to thread_exit is made by each thread after completing
 * the execution of routine
 */
void thread_exit(void *ret)
{
    spin_acquire(&__globalLock);
    void *addr = returnCustomTidAddress(&__tidList, gettid());
    if (!addr) {
        spin_release(&__globalLock);
        return;
    }
    if (ret) {
        node *insertedNode = returnCustomNode(&__tidList, gettid());
        insertedNode->retVal = ret;
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    spin_release(&__globalLock);
    kill(SIGINT, gettid());
    return;
}

#include <stdatomic.h>

#define safeprintf(printlock, f_, ...) \
    spin_acquire(printlock);           \
    printf((f_), ##__VA_ARGS__);       \
    spin_release(printlock);

static mutex_t lock, rwlock;
static spin_t printlock;

static int readers = 0;
static int n_readers_in = 0, n_writers_in = 0;

static void f1()
{
    mutex_acquire(&lock);
    readers += 1;
    if (readers == 1)
        mutex_acquire(&rwlock);
    mutex_release(&lock);

    safeprintf(&printlock, "Reader process in\n");
    atomic_fetch_add(&n_readers_in, 1);
    mutex_acquire(&lock);
    readers -= 1;
    if (readers == 0)
        mutex_release(&rwlock);
    mutex_release(&lock);
    atomic_fetch_sub(&n_readers_in, 1);
    safeprintf(&printlock, "Reader process out\n");
}

static void f2()
{
    mutex_acquire(&rwlock);
    atomic_fetch_add(&n_writers_in, 1);
    safeprintf(&printlock, "Writer process in\n");
    mutex_release(&rwlock);
    atomic_fetch_sub(&n_writers_in, 1);
    safeprintf(&printlock, "Writers process out\n");
}
int main()
{
    mutex_init(&lock);
    mutex_init(&rwlock);
    spin_init(&printlock);
    atomic_init(&n_readers_in, 0);
    atomic_init(&n_writers_in, 0);
    thread readers[5], writers[5];
    for (int i = 0; i < 5; i++) {
        thread_create(&readers[i], f1, NULL);
        thread_create(&writers[i], f2, NULL);
    }
    for (int i = 0; i < 5; i++) {
        thread_join(writers[i], NULL);
        thread_join(readers[i], NULL);
    }
    return 0;
}