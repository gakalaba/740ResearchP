#include "pin.H"
#include <stdio.h>
#include <map>
#include <iostream>
#include <stdbool.h>
using namespace std;

// A big table for memory
map <ADDRINT *, ADDRINT> memory;
// Initalize all objects

int total = 0;

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

ADDRINT DoLoad(REG reg, ADDRINT *addr) {
    // print_mem();
    ADDRINT value;
    map<long unsigned int *, long unsigned int>::iterator it =
        memory.find(addr);
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
        cout << "SafeCopy " << addr << " with value " << value << "\n";
    if (it != memory.end()) {
        value = it->second;
        cout << "FOUND " << addr << " with value " << value << "\n";
    }

    fprintf(trace, "\nEmulate loading %d from addr %p to %s\n", (int)value,
            addr, REG_StringShort(reg).c_str());

    return value;
}

ADDRINT DoStore(CONTEXT *ctxt, REG reg, ADDRINT *addr) {
    // print_mem();
    ADDRINT value;

    UINT32 rw = REG_Size(reg);
    if (rw < 8)
        value = PIN_GetContextReg(ctxt, REG_FullRegName(reg));
    else
        value = PIN_GetContextReg(ctxt, reg);
    if (rw == 2)
        value &= 0xFFFF;
    else if (rw == 4)
        value &= 0xFFFFFFFF;
    fprintf(trace, "\nEmulate storing %d TO %p from %s\n", (int)value, addr,
            REG_StringShort(reg).c_str());
    memory.insert(make_pair(addr, value));
    print_mem();
    return value;
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoadStore(INS ins, VOID *v) {

    // Find the instructions that move a value from memory to a register
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryRead(ins) &&
        INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1)) {
        // op0 <- *op1
        // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad), IARG_UINT32,
                       REG(INS_OperandReg(ins, 0)), IARG_MEMORYREAD_EA,
                       IARG_RETURN_REGS, INS_OperandReg(ins, 0), IARG_END);
        // Delete the instruction
        INS_Delete(ins);
    }
    // moves value from register to memory (store)
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryWrite(ins) &&
        INS_OperandIsReg(ins, 1) && INS_OperandIsMemory(ins, 0)) {
        // fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoStore), IARG_CONTEXT,
                       IARG_UINT32, REG(INS_OperandReg(ins, 1)),
                       IARG_MEMORYWRITE_EA, IARG_RETURN_REGS,
                       INS_OperandReg(ins, 1), IARG_END);
        // Delete the instruction
        // INS_Delete(ins);
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

    INS_AddInstrumentFunction(EmulateLoadStore, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
