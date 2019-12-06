#include "pin.H"
#include <stdio.h>
#include <map>
#include <iostream>
#include <stdbool.h>
#include "uthash/include/uthash.h"
using namespace std;

#define MAX_THREADS (4)
#define MAX_DELAY (10)
#define NET_DELAY (5)

PIN_LOCK mem_lock;

struct mem_elem {
    ADDRINT *address;  // key
    ADDRINT val;
    UT_hash_handle hh;
};

struct pending_addr {
    ADDRINT *addr;
    UINT32 size;
};

UINT64 cycle_count[MAX_THREADS];

// A big table for memory
struct mem_elem *memory;
struct pending_addr pending_addrs[MAX_THREADS];
// Initalize all objects

void add_store(ADDRINT *addr, ADDRINT val, THREADID tid) {
    cout << "storing...\n";
    struct mem_elem *me;
    struct mem_elem *new_me = (struct mem_elem *)malloc(sizeof(mem_elem));
    HASH_FIND_INT(memory, &addr, me);
    PIN_GetLock(&mem_lock, tid);
    if (me != NULL) {
        me->val = val;
        PIN_ReleaseLock(&mem_lock);
        free(new_me);
    } else {
        new_me->address = addr;
        new_me->val = val;
        HASH_ADD_INT(memory, address, new_me);
        PIN_ReleaseLock(&mem_lock);
    }
}

int read_map(ADDRINT *addr, ADDRINT *value) {
    cout << "tryna read this yung thug\n";
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
    for (me = src; me != NULL; me = (struct mem_elem *)(me->hh.next)) {
        cout << "addr = " << src->address << "   value = " << src->val << "\n";
    }
    PIN_ReleaseLock(&mem_lock);
    cout << "\n";
    return;
}

ADDRINT get_val(ADDRINT val, UINT32 size) {
    UINT32 mask = 0xFFFFFFFF << size;
    return ((~mask) & val);
}

VOID DoLoad1(ADDRINT *addr, UINT32 size, THREADID tid) {

    cycle_count[(tid % MAX_THREADS)] += MAX_DELAY;
    return;
    // print_mem();
    ADDRINT value;

    // check if it's in our hashmap
    if (read_map(addr, &value) < 0) {
        PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
        value = get_val(value, size);
    } else {
        value = get_val(value, size);
        cout << value << " value from map\n";
        // PIN_SafeCopy(addr, &value, sizeof(ADDRINT));
    }
    return;

    fprintf(trace, "\nEmulate loading %d from addr %p\n", (int)value, addr);

    // return value;
}

VOID DoLoad2(ADDRINT *addr1, ADDRINT *addr2, UINT32 size, THREADID tid) {
    // print_mem();
    cycle_count[(tid % MAX_THREADS)] += MAX_DELAY;
    return;
    ADDRINT value1, value2;

    // check if it's in our hashmap
    if (read_map(addr1, &value1) < 0) {
        PIN_SafeCopy(&value1, addr1, sizeof(ADDRINT));
        value1 = get_val(value1, size);
    } else {
        value1 = get_val(value1, size);
    }

    if (read_map(addr2, &value2) < 0) {
        PIN_SafeCopy(&value2, addr2, sizeof(ADDRINT));
        value2 = get_val(value2, size);
    } else {
        value2 = get_val(value2, size);
        // PIN_SafeCopy(addr2, &value2, sizeof(ADDRINT));
    }

    fprintf(trace,
            "\nEmulate loading 2 vals: %d from addr %p  %d from addr %p\n",
            (int)value1, addr1, (int)value2, addr2);

    // return value;
}

VOID BeforeStore(ADDRINT *addr, UINT32 size, THREADID tid) {
    cycle_count[(tid % MAX_THREADS)] += MAX_DELAY + NET_DELAY;
    return;
    pending_addrs[(tid % MAX_THREADS)].addr = addr;
    pending_addrs[(tid % MAX_THREADS)].size = size;
}

VOID AfterStore(THREADID tid) {

    ADDRINT *addr = pending_addrs[(tid % MAX_THREADS)].addr;
    UINT32 size = pending_addrs[(tid % MAX_THREADS)].size;

    // ADDRINT value = get_val((*addr), size);
    ADDRINT value;
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    value = get_val(value, size);
    value = 12;
    add_store(addr, value, tid);
}

VOID InstrIncr(THREADID tid) { cycle_count[(tid % MAX_THREADS)] += 1; }

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
        if (INS_IsAtomicUpdate(ins)) {
            cout << "HALALALALALLA\n";
        }

        if (!INS_IsMemoryRead(ins) && !INS_HasMemoryRead2(ins) &&
            !INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(InstrIncr),
                           IARG_THREAD_ID, IARG_END);
        }
        // Find the instructions that move a value from memory to a register
        fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
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
            // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(BeforeStore),
                           IARG_UINT32, IARG_MEMORYWRITE_EA,
                           IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);

            // INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(AfterStore),
            //               IARG_THREAD_ID, IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(trace, "#eof\n");
    fclose(trace);
    for (int i = 0; i < MAX_THREADS; i++) {
        cout << "i = " << i << "cycle_count = " << cycle_count[i] << "\n";
    }
    return;
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

    INS_AddInstrumentFunction(EmulateLoadStore, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
