#include "pin.H"
#include <stdio.h>
#include <map>
#include <cstdlib>
#include <iostream>
#include <stdbool.h>
#include <ctime>
#include "uthash/include/uthash.h"
using namespace std;

#define MAX_DELAY (20)
#define MAX_NET_DELAY (10)
#define MAX_THREADS (1024)

struct mem_elem *memory[MAX_THREADS];

struct mem_elem {
    ADDRINT *addr; // key
    ADDRINT val;
    UT_hash_handle hh;
};

struct queue_elem {
    ADDRINT val;
    ADDRINT *addr;
    UINT64 cycle;
};

struct mem_queue_elem {
    ADDRINT val;
    UINT64 cycle;
    THREADID tid;
};

struct pending_addr {
    ADDRINT *addr;
    UINT32 size;
};

// array of write queues per thread
queue <struct queue_elem> write_qs[MAX_THREADS];
bool thread_alive[MAX_THREADS];

// Initalize all objects
PIN_LOCK ins_lock;
int total = 0;
bool in_main = false;
FILE *trace;
UINT64 ins_count[MAX_THREADS];
THREADID main_tid;

struct pending_addr *pending_addrs[MAX_THREADS];

void add_store(ADDRINT *addr, ADDRINT val, THREADID tid) {
    struct mem_elem *me;
    HASH_FIND_INT(memory[(tid % MAX_THREADS)], &addr, me);
    if (me == NULL) {
        me = (struct mem_elem *)malloc(sizeof(mem_elem));
        me -> addr = addr;
        me -> val = val;
        HASH_ADD_INT(memory[(tid % MAX_THREADS)], addr, me);
    } else {
        me -> val = val;
    }
}

int get_load(ADDRINT *addr, ADDRINT *value, THREADID tid) {
    struct mem_elem *me;
    HASH_FIND_INT(memory[(tid % MAX_THREADS)], &addr, me);
    if (me == NULL) {
        return -1;
    }
    *value = me -> val;
    return 0;
}

void print_mem() {
    if (total > 100) return;
    total++;
    cout << "printing map:\n";
    map<long unsigned int *, long unsigned int>::iterator it;
    for (it = memory.begin(); it != memory.end(); it++) {
        cout << "addr = " << it->first << "   value = " << it->second << "\n";
    }
    cout << "\n";
    return;
}

ADDRINT get_val(ADDRINT val, UINT32 size) {
    UINT32 mask = 0xFFFFFFFF << size;
    return ((~mask) & val);
}

void copy_memory(THREADID tid) {
    struct mem_elem *src = memory[(main_tid % MAX_THREADS)];
    struct mem_elem *dst = memory[(tid % MAX_THREADS)];
    struct mem_elem *me;
    dst = NULL;
    for(me = src; me != NULL; me = (struct mem_elem *)(me->hh.next)) {
        add_store(src -> addr, src -> val, tid);
    }
}

ADDRINT DoLoad1(ADDRINT *addr, UINT32 size, THREADID tid) {
    // print_mem();
    ADDRINT value;

    // check if it's in our hashmap
    if(get_load(addr, &value, tid) < 0) {
        //PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
        value = get_val((*addr), size);
    } else {
        value = get_val(value, size);
    }

    fprintf(trace, "\nEmulate loading %d from addr %p\n", (int)value,
            addr);

    return value;
}

VOID DoLoad2(ADDRINT *addr1, ADDRINT *addr2, UINT32 size, THREADID tid) {
    // print_mem();
    ADDRINT value1, value2;

    // check if it's in our hashmap
    if(get_load(addr1, &value1, tid) < 0) {
        //PIN_SafeCopy(&value1, addr1, sizeof(ADDRINT));
        value1 = get_val((*addr1), size);
    } else {
        value1 = get_val(value1, size);
    }

    if(get_load(addr2, &value2, tid) < 0) {
        //PIN_SafeCopy(&value2, addr2, sizeof(ADDRINT));
        value2 = get_val((*addr2), size);
    } else {
        value2 = get_val(value2, size);
    }

    fprintf(trace, "\nEmulate loading 2 vals: %d from addr %p  %d from addr
            %p\n", (int)value1, addr1, (int)value2, addr2);

    //return value;
}

UINT64 get_base(int tid_index) {
    queue <struct queue_elem> write_q = write_qs[tid_index];
    if (write_q.empty()) {
        return ins_count[tid_index];
    }
    // must preserve write-write ordering
    struct queue_elem e = write_q.back();
    return e.cycle + 1;
}

VOID add_to_queues(ADDRINT *addr, ADDRINT value, UINT64 write_delay) {
    for(int i = 0; i < MAX_THREADS; i++) {
        if (thread_alive(i)) {
             // Queue the write
            UINT64 last_time = get_base(i);
            UINT64 network_delay = (UINT64)(rand() % MAX_NET_DELAY);
            UINT64 pop_cycle = last_time + write_delay + network_delay;

            struct queue_elem *e = malloc(sizeof(struct queue_elem));
            e -> addr = addr;
            e -> val = value;
            e -> cycle = pop_cycle;

            // lock
            queue <struct queue_elem> q = write_qs[i];
            q.push(e);
        }
    }
}

VOID BeforeStore(ADDRINT *addr, UINT32 size, THREADID tid) {
    pending_addrs[(tid % MAX_THREADS)] -> addr = addr;
    pending_addrs[(tid % MAX_THREADS)] -> size = size;
}

VOID AfterStore(THREADID tid) {
    ADDRINT *addr = pending_addrs[(tid % MAX_THREADS)] -> addr;
    UINT32 size = pending_addrs[(tid % MAX_THREADS)] -> size;

    ADDRINT value = get_val((*addr), size);

    // Queue the write
    UINT64 last_time = get_base((tid % MAX_THREADS));
    UINT64 pop_cycle = (UINT64)(rand() % MAX_DELAY) + last_time;

    struct queue_elem *e = malloc(sizeof(struct queue_elem));
    e -> addr = addr;
    e -> val = value;
    e -> cycle = pop_cycle;

    // lock
    queue <struct queue_elem> q = write_qs[(tid % MAX_THREADS)];
    q.push(e);

    // PC - add to everyone's queue
    add_to_queues(addr, value, (pop_cycle - last_time));

    //return value;
}

VOID processQueue(THREADID tid) {
    PIN_GetLock(&ins_lock, tid);
    ins_count[(tid % MAX_THREADS)]++;
    PIN_ReleaseLock(&ins_lock);
    queue <struct queue_elem> write_q = write_qs[(tid % MAX_THREADS)];
    if (!write_q.empty()) {
        struct queue_elem e = write_q.front();
        if (ins_count[(tid % MAX_THREADS)] >= e.cycle) {
            // DO THE WRITE
            add_store(e->addr, e->val, tid);
            // Take it out of the queue
            write_q.pop();
        }
    }
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoadStore(INS ins, VOID *v) {
    if(in_main) {

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(processQueue),
                IARG_THREAD_ID, IARG_END);
        // Find the instructions that move a value from memory to a register
        if (INS_IsMemoryRead(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad1), IARG_UINT32,
                       IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
            // Delete the instruction
            //INS_Delete(ins);
        }
        if (INS_HasMemoryRead2(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad2), IARG_UINT32,
                       IARG_MEMORYREAD_EA, IARG_MEMORYREAD2_EA,
                       IARG_MEMORYREAD_SIZE, IARG_END);
            // Delete the instruction
            //INS_Delete(ins);
        }
// moves value from register to memory (store)
        if (INS_IsMemoryWrite(ins)) {
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoStore),
                    IARG_UINT32, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
                    IARG_END);
        // Delete the instruction
        // INS_Delete(ins);
        }
    }
}

VOID BeforeMain(int size, THREADID threadid) {
    // program shouldn't be multithreaded when we hit main
    in_main = true;
    cout << "in main\n";
}

VOID AfterMain(ADDRINT ret) {
    in_main = false;
    cout << "main done\n";
}

VOID ImageLoad(IMG img, VOID *) {
    RTN rtn = RTN_FindByName(img, "main");

    if ( RTN_Valid( rtn )) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(BeforeMain),
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(AfterMain),
            IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(rtn);
    }
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(trace, "#eof\n");
    fclose(trace);
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

    // Register ImageLoad to be called when each image is loaded.
    IMG_AddInstrumentFunction(ImageLoad, 0);

    INS_AddInstrumentFunction(EmulateLoadStore, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
