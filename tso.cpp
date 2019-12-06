#include "pin.H"
#include <stdio.h>
#include <map>
#include <cstdlib>
#include <iostream>
#include <stdbool.h>
#include <ctime>
#include <queue>
#include "uthash/include/uthash.h"
using namespace std;

#define MAX_DELAY (10)
#define MAX_NET_DELAY (5)
#define MAX_THREADS (4)
UINT64 cycle_count[MAX_THREADS];

struct queue_elem {
    ADDRINT val;
    ADDRINT *addr;
    UINT64 cycle;
};

struct mem_elem {
    ADDRINT *addr;  // key
    ADDRINT val;
    UT_hash_handle hh;
};

struct pending_addr {
    ADDRINT *addr;
    UINT32 size;
};

// A big table for memory
struct mem_elem *memory;
PIN_LOCK mem_lock;
queue<struct queue_elem *> write_qs[MAX_THREADS];
struct pending_addr pending_addrs[MAX_THREADS];
THREADID main_tid;
bool thread_alive[MAX_THREADS];

void add_store(ADDRINT *addr, ADDRINT val, THREADID tid) {
    struct mem_elem *me;
    struct mem_elem *new_me = (struct mem_elem *)malloc(sizeof(mem_elem));
    HASH_FIND_INT(memory, &addr, me);
    PIN_GetLock(&mem_lock, tid);
    if (me != NULL) {
        me->val = val;
        PIN_ReleaseLock(&mem_lock);
        free(new_me);
    } else {
        me->addr = addr;
        me->val = val;
        HASH_ADD_INT(memory, addr, me);
        PIN_ReleaseLock(&mem_lock);
    }
}

int get_load(ADDRINT *addr, ADDRINT *value) {
    struct mem_elem *me;
    HASH_FIND_INT(memory, &addr, me);
    PIN_GetLock(&mem_lock, 1);
    if (me == NULL) {
        PIN_ReleaseLock(&mem_lock);
        return -1;
    }
    *value = me->val;
    PIN_ReleaseLock(&mem_lock);
    return 0;
}

// Initalize all objects
PIN_LOCK ins_lock;
int total = 0;
bool in_main = false;
FILE *trace;
UINT64 ins_count[MAX_THREADS];

void print_mem() {
    if (total > 100) return;
    total++;
    cout << "printing map:\n";
    struct mem_elem *me;
    PIN_GetLock(&mem_lock, 1);
    struct mem_elem *src = memory;
    for (me = src; me != NULL; me = (struct mem_elem *)(me->hh.next)) {
        cout << "addr = " << src->addr << "   value = " << src->val << "\n";
    }
    PIN_ReleaseLock(&mem_lock);
    cout << "\n";
    return;
}

// We must always size the value from memory properly
ADDRINT get_val(ADDRINT val, UINT32 size) {
    UINT32 mask = 0xFFFFFFFF << size;
    return ((~mask) & val);
}

VOID DoLoad1(ADDRINT *addr, UINT32 size, THREADID tid) {
    cycle_count[(tid % MAX_THREADS)] += MAX_DELAY;
    return;
    ADDRINT value;

    // check if it's in our hashmap
    if (get_load(addr, &value) < 0) {
        // PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
        value = get_val((*addr), size);
    } else {
        value = get_val(value, size);
    }

    fprintf(trace, "\nEmulate loading %d from addr %p\n", (int)value, addr);
    // return value;
}

VOID DoLoad2(ADDRINT *addr1, ADDRINT *addr2, UINT32 size, THREADID tid) {
    cycle_count[(tid % MAX_THREADS)] += MAX_DELAY;
    return;
    // print_mem();
    ADDRINT value1, value2;

    // check if it's in our hashmap
    if (get_load(addr1, &value1) < 0) {
        // PIN_SafeCopy(&value1, addr1, sizeof(ADDRINT));
        value1 = get_val((*addr1), size);
    } else {
        value1 = get_val(value1, size);
    }

    if (get_load(addr2, &value2) < 0) {
        // PIN_SafeCopy(&value2, addr2, sizeof(ADDRINT));
        value2 = get_val((*addr2), size);
    } else {
        value2 = get_val(value2, size);
    }

    fprintf(trace,
            "\nEmulate loading 2 vals: %d from addr %p  %d from addr %p\n",
            (int)value1, addr1, (int)value2, addr2);

    // return value;
}

UINT64 get_base(int tid_index) {
    queue<struct queue_elem *> write_q = write_qs[tid_index];
    if (write_q.empty()) {
        return ins_count[tid_index];
    }
    // must preserve write-write ordering
    struct queue_elem *e = write_q.back();
    return e->cycle + 1;
}
/*
VOID BeforeStore(ADDRINT *addr, UINT32 size, THREADID tid) {
    pending_addrs[(tid % MAX_THREADS)].addr = addr;
    pending_addrs[(tid % MAX_THREADS)].size = size;
}*/

VOID BeforeStore(ADDRINT *addr, UINT32 size, THREADID tid) {
    cout << " HELOELHE\n";
    // ADDRINT *addr = pending_addrs[(tid % MAX_THREADS)].addr;
    // UINT32 size = pending_addrs[(tid % MAX_THREADS)].size;

    // ADDRINT value = get_val((*addr), size);

    // Queue the write
    UINT64 last_time = get_base((tid % MAX_THREADS));
    cout << "       last_time = " << last_time << " \n";
    UINT64 write_delay = (UINT64)(rand() % MAX_DELAY);
    UINT64 network_delay = (UINT64)(rand() % MAX_NET_DELAY);
    // Still need network delay... because all the writes will see this
    UINT64 pop_cycle = last_time + write_delay + network_delay;

    struct queue_elem *e =
        (struct queue_elem *)malloc(sizeof(struct queue_elem));
    // e->addr = addr;
    // e->val = value;
    e->cycle = pop_cycle;

    // don't need lock, touching your own write queue without contention
    queue<struct queue_elem *> q = write_qs[(tid % MAX_THREADS)];
    cout << "DS thread id " << (tid % MAX_THREADS) << "Pushing pop cycle of "
         << pop_cycle << " \n";
    q.push((e));
    write_qs[(tid % MAX_THREADS)] = q;
    if (q.empty()) {
        cout << "NONONO\n";
    }
    struct queue_elem *tester = q.back();
    cout << "what i just pushed has pop_cycle " << tester->cycle << " \n";
    queue<struct queue_elem *> the_q = write_qs[(tid % MAX_THREADS)];
    if (the_q.empty()) {
        cout << "LAMOOOO\n";
    } else {
        cout << "ok...........\n\n";
    }
}

VOID ProcessQueue(THREADID tid) {
    cycle_count[(tid % MAX_THREADS)]++;
    ins_count[(tid % MAX_THREADS)]++;
    cout << "PQ thread id " << tid << " at ins count "
         << ins_count[(tid % MAX_THREADS)] << " \n";
    queue<struct queue_elem *> write_q = write_qs[(tid % MAX_THREADS)];
    if (!write_q.empty()) {
        struct queue_elem *e = write_q.front();
        cout << "sees prev write to pop at" << e->cycle << " cycles\n";
        if (ins_count[(tid % MAX_THREADS)] >= e->cycle) {
            cout << "popped \n";
            // DO THE WRITE
            // add_store(e.addr, e.val, tid);
            // Take it out of the queue
            write_q.pop();
            write_qs[(tid % MAX_THREADS)] = write_q;
            free(e);
        }
    }
}

VOID FlushQueue(THREADID tid) {
    cout << "                                                                  "
            "                                              FLUSH\n";
    queue<struct queue_elem *> write_q = write_qs[(tid % MAX_THREADS)];
    cout << "the overall cycle count is at " << cycle_count[(tid % MAX_THREADS)]
         << " \n";
    struct queue_elem *e = NULL;
    while (!write_q.empty()) {
        e = write_q.front();
        // Take it out of the queue
        write_q.pop();
        cout << "just popped elem to cycle time " << e->cycle << "\n";
        write_qs[(tid % MAX_THREADS)] = write_q;
        // add_store(e.addr, e.val, tid);
    }
    if (e != NULL) {
        UINT64 stall_time = e->cycle - ins_count[(tid % MAX_THREADS)];
        cycle_count[(tid % MAX_THREADS)] += stall_time;

        cout << "Last elem had pop_cycle = " << e->cycle << " \n";
    }
    cout << "NOW the overall cycle count is at "
         << cycle_count[(tid % MAX_THREADS)] << " \n";
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoadStore(INS ins, VOID *v) {
    RTN insRoutine = INS_Rtn(ins);
    if (!RTN_Valid(insRoutine)) return;
    SEC insSection = RTN_Sec(insRoutine);
    IMG insImage = SEC_Img(insSection);
    in_main = IMG_IsMainExecutable(insImage);

    if (in_main) {
        queue<struct queue_elem *> q = write_qs[0];
        if (q.empty()) {
            cout << "starting instr, q is empty\n";
        } else {
            cout << "starting instr, q is NOT empty\n";
        }

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ProcessQueue),
                       IARG_THREAD_ID, IARG_END);

        if (INS_IsAtomicUpdate(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(FlushQueue),
                           IARG_THREAD_ID, IARG_END);
        }

        // Find the instructions that move a value from memory to a register

        if (INS_IsMemoryRead(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad1), IARG_UINT32,
                           IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
                           IARG_THREAD_ID, IARG_END);
            // Delete the instruction
            // INS_Delete(ins);
        }
        if (INS_HasMemoryRead2(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad2), IARG_UINT32,
                           IARG_MEMORYREAD_EA, IARG_MEMORYREAD2_EA,
                           IARG_THREAD_ID, IARG_MEMORYREAD_SIZE, IARG_END);
            // Delete the instruction
            // INS_Delete(ins);
        }
        // moves value from register to memory (store)
        if (INS_IsMemoryWrite(ins)) {
            cout << "STORINGORINGOINGO\n";
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(BeforeStore),
                           IARG_UINT32, IARG_MEMORYWRITE_EA,
                           IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
            /*
                        IPOINT where = IPOINT_AFTER;
                        if (!INS_HasFallThrough(ins)) {
                            where = IPOINT_TAKEN_BRANCH;
                        }
                        cout << "where ===== " << where << " \n";
                        INS_InsertCall(ins, where, AFUNPTR(AfterStore),
               IARG_THREAD_ID,
                                       IARG_END);*/
        }
    }
}

VOID BeforeMain(int size, THREADID threadid) {
    // program shouldn't be multithreaded when we hit main
    in_main = true;
    main_tid = threadid;
    cout << "in main\n";
}

VOID AfterMain(ADDRINT ret) {
    in_main = false;
    cout << "main done\n";
}

VOID ImageLoad(IMG img, VOID *) {
    RTN rtn = RTN_FindByName(img, "main");

    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(BeforeMain),
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID,
                       IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(AfterMain),
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(rtn);
    }
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(trace, "#eof\n");
    fclose(trace);
    for (int i = 0; i < MAX_THREADS; i++) {
        cout << "i = " << i << "cycle_count = " << cycle_count[i] << "\n";
        queue<struct queue_elem *> q = write_qs[i];
        if (!q.empty()) {
            cout << "Still straggling writes\n";
        }
    }
    return;

    struct mem_elem *me, *next_me;
    me = memory;
    PIN_GetLock(&mem_lock, 1);
    while (me != NULL) {
        next_me = (struct mem_elem *)(me->hh.next);
        free(me);
        me = next_me;
    }
    PIN_ReleaseLock(&mem_lock);
}

/* =====================================================================
 */
/* Print Help Message */
/* =====================================================================
 */

INT32 Usage() {
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" +
              KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* =====================================================================
 */
/* Main */
/* =====================================================================
 */

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();

    srand(time(NULL));

    trace = fopen("pinatrace.out", "w");

    // Initialize thread array variables
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_alive[i] = false;
        ins_count[i] = 0;
    }

    // Register ImageLoad to be called when each image is loaded.
    IMG_AddInstrumentFunction(ImageLoad, 0);

    INS_AddInstrumentFunction(EmulateLoadStore, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
