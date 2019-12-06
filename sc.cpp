#include "pin.H"
#include <stdio.h>
#include <map>
#include <iostream>
#include <stdbool.h>
#include "uthash/include/uthash.h"
using namespace std;

#define MAX_THREADS (1024)

PIN_LOCK mem_lock;

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
struct pending_addr pending_addrs[MAX_THREADS];
// Initalize all objects

void add_store(ADDRINT *addr, ADDRINT val, THREADID tid) {
    struct mem_elem *me;
    struct mem_elem *new_me = (struct mem_elem *)malloc(sizeof(mem_elem));
    HASH_FIND_INT(memory, &addr, me);
    PIN_GetLock(&mem_lock, tid);
    if (me != NULL) {
        me->val = val;
        PIN_ReleaseLock(&mem_lock, tid);
        free(new_me);
    } else {
        new_me->addr = addr;
        new_me->val = val;
        HASH_ADD_INT(memory, addr, me);
        PIN_ReleaseLock(&mem_lock, tid);
    }
}

int read_map(ADDRINT *addr, ADDRINT *value) {
    struct mem_elem *me;
    HASH_FIND_INT(memory, &addr, me);
    PIN_GetLock(&mem_lock, 1);
    if (me == NULL) {
        PIN_ReleaseLock(&mem_lock, 1);
        return -1;
    }
    *value = me->val;
    PIN_ReleaseLock(&mem_lock, 1);
    return 0;
}

int total = 0;
bool in_main = false;
FILE *trace;

void print_mem() {
    if (total > 100) return;
    total++;
    cout << "printing map:\n";
    struct mem_elem *me;
    struct mem_elem *src = memory;
    PIN_GetLock(&mem_lock, 1);
    for (me = src; me != NULL; (struct mem_elem *)(me->hh.next)) {
        cout << "addr = " << src->addr << "   value = " << src->val << "\n";
    }
    PIN_ReleaseLock(&mem_lock, 1);
    cout << "\n";
    return;
}

ADDRINT get_val(ADDRINT val, UINT32 size) {
    UINT32 mask = 0xFFFFFFFF << size;
    return ((~mask) & val);
}

ADDRINT DoLoad1(ADDRINT *addr, UINT32 size) {

    // print_mem();
    ADDRINT value;

    // check if it's in our hashmap
    if (read_map(addr, &value) < 0) {
        // PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
        value = get_val((*addr), size);
    } else {
        value = get_val(value, size);
    }

    fprintf(trace, "\nEmulate loading %d from addr %p\n", (int)value, addr);

    return value;
}

ADDRINT DoLoad2(ADDRINT *addr1, ADDRINT *addr2, UINT32 size) {
    // print_mem();
    ADDRINT value1, value2;

    // check if it's in our hashmap
    if (read_map(addr1, &value1) < 0) {
        // PIN_SafeCopy(&value1, addr1, sizeof(ADDRINT));
        value1 = get_val((*addr1), size);
    } else {
        value1 = get_val(value1, size);
    }

    if (read_map(addr2, &value2) < 0) {
        // PIN_SafeCopy(&value2, addr2, sizeof(ADDRINT));
        value2 = get_val((*addr2), size);
    } else {
        value2 = get_val(value2, size);
    }

    fprintf(trace, "\nEmulate loading 2 vals: %d from addr %p  %d from addr
            %p\n", (int)value1, addr1, (int)value2, addr2);

    return value;
}

VOID BeforeStore(ADDRINT *addr, UINT32 size, THREADID tid) {
    pending_addrs[(tid % MAX_THREADS)].addr = addr;
    pending_addrs[(tid % MAX_THREADS)].size = size;
}

VOID AfterStore(THREADID tid) {
    ADDRINT *addr = pending_addrs[(tid % MAX_THREADS)].addr;
    UINT32 size = pending_addrs[(tid % MAX_THREADS)].size;

    ADDRINT value = get_val((*addr), size);

    add_store(addr, value)
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoadStore(INS ins, VOID *v) {
    if (in_main) {
        // Find the instructions that move a value from memory to a register
        if (INS_IsMemoryRead(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad1), IARG_UINT32,
                           IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
            // Delete the instruction
            // INS_Delete(ins);
        }
        if (INS_HasMemoryRead2(ins)) {
            // op0 <- *op1
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad2), IARG_UINT32,
                           IARG_MEMORYREAD_EA, IARG_MEMORYREAD2_EA,
                           IARG_MEMORYREAD_SIZE, IARG_END);
            // Delete the instruction
            // INS_Delete(ins);
        }
        // moves value from register to memory (store)
        if (INS_IsMemoryWrite(ins)) {
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(BeforeStore),
                           IARG_UINT32, IARG_MEMORYWRITE_EA,
                           IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);

            INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(AfterStore),
                           IARG_THREAD_ID, IARG_END);
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
    struct mem_elem *me, next_me;
    me = memory;
    PIN_GetLock(&mem_lock, 1);
    while (me != NULL) {
        next_me = (struct mem_elem *)(me->hh.next);
        free(me);
        me = next_me
    }
    PIN_ReleaseLock(&mem_lock, 1);
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

    trace = fopen("pinatrace.out", "w");

    // Register ImageLoad to be called when each image is loaded.
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // INS_AddInstrumentFunction(EmulateLoadStore, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
