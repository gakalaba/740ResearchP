#include "pin.H"
#include <stdio.h>
#include <map>
#include <iostream>
#include <stdbool.h>
#include "uthash/include/uthash.h"
using namespace std;

// A big table for memory
map <ADDRINT *, ADDRINT> memory;
// Initalize all objects

int total = 0;
bool in_main = false;
FILE *trace;

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

ADDRINT DoLoad1(ADDRINT *addr, UINT32 size) {
    // print_mem();
    ADDRINT value;
    map<long unsigned int *, long unsigned int>::iterator it =
        memory.find(addr);
    //PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    cout << "SafeCopy " << addr << " with value " << value << "\n";
    if (it != memory.end()) {
        value = it->second;
        cout << "FOUND " << addr << " with value " << value << "\n";
    } else {
        value = get_val((*addr), size);
    }

    fprintf(trace, "\nEmulate loading %d from addr %p\n", (int)value,
            addr);

    return value;
}

VOID DoLoad2(ADDRINT *addr1, ADDRINT *addr2, UINT32 size) {
    // print_mem();
    ADDRINT value1, value2;
    map<long unsigned int *, long unsigned int>::iterator it =
        memory.find(addr1);
    PIN_SafeCopy(&value1, addr1, sizeof(ADDRINT));
        cout << "SafeCopy " << addr1 << " with value " << value1 << "\n";
    if (it != memory.end()) {
        value1 = it->second;
        cout << "FOUND " << addr1 << " with value " << value1 << "\n";
    } else {
        value1 = get_val((*addr1), size);
    }

    it = memory.find(addr2);
    //PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    cout << "SafeCopy " << addr2 << " with value " << value2 << "\n";
    if (it != memory.end()) {
        value2 = it->second;
        cout << "FOUND " << addr2 << " with value " << value2 << "\n";
    } else {
        value2 = get_val((*addr2), size);
    }

    fprintf(trace, "\nEmulate loading 2 vals: %d from addr %p  %d from addr
            %p\n", (int)value1, addr1, (int)value2, addr2);

    //return value;
}

VOID DoStore(ADDRINT *addr, UINT32 size) {
    // print_mem();
    ADDRINT value;

    //memory.insert(make_pair(addr, value));
    print_mem();
    //return value;
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoadStore(INS ins, VOID *v) {
    if(in_main) {
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

    trace = fopen("pinatrace.out", "w");

    // Register ImageLoad to be called when each image is loaded.
    IMG_AddInstrumentFunction(ImageLoad, 0);

    //INS_AddInstrumentFunction(EmulateLoadStore, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
