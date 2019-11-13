#include "pin.H"
#include <stdio.h>
#include <map>
#include <iostream>
#include <stdbool.h>
using namespace std;

// A big table for memory
map<long unsigned int *, long unsigned int> memory;

// Initalize all objects

FILE *trace;

ADDRINT DoLoad(REG reg, ADDRINT *addr) {
    fprintf(trace, "\nEmulate loading from addr %p to %s\n", addr,
            REG_StringShort(reg).c_str());
    ADDRINT value = 9;
    // PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    // value = memory.find(addr)->second;

    // fprintf(trace, "\nvalue = %d\n", (int)value);
    return value;
}

ADDRINT DoStore(CONTEXT *ctxt, REG reg, ADDRINT *addr) {
    cout << "HI\n";
    cout << "addr " << addr << " register " << REG_StringShort(reg).c_str()
         << "\n";
    fprintf(trace, "\nEmulate storing TO %p from %s\n", addr,
            REG_StringShort(reg).c_str());
    ADDRINT value;

    cout << "REg" << reg << "\n";
    UINT32 rw = REG_Size(reg);
    cout << "width = " << rw << "\n";
    if (rw < 8)
        value = PIN_GetContextReg(ctxt, REG_FullRegName(reg));
    else
        value = PIN_GetContextReg(ctxt, reg);
    if (rw == 2)
        value &= 0xFFFF;
    else if (rw == 4)
        value &= 0xFFFFFFFF;

    // value = PIN_GetContextReg(ctxt, reg);
    cout << "reg val from ContextRegval" << value << "\n";
    // fprintf(trace, "\nvalue: %d\n", value);

    cout << "BYE\n";
    // memory.insert(make_pair(addr, value));
    return value;
}

////=======================================================
//// Instrumentation routines
////=======================================================
VOID EmulateLoad(INS ins, VOID *v) {
    /*UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            // Run cacheRoutine for Data (load) cache
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                     (AFUNPTR)callDataReadRoutine,
                                     IARG_MEMORYOP_EA, memOp, IARG_END);
        }
    }*/

    // Find the instructions that move a value from memory to a register
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryRead(ins) &&
        INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1)) {
        // op0 <- *op1
        fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
        /*INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad), IARG_UINT32,
                       REG(INS_OperandReg(ins, 0)), IARG_MEMORYREAD_EA,
                       IARG_RETURN_REGS, INS_OperandReg(ins, 0), IARG_END);
        // Delete the instruction
        INS_Delete(ins);*/
    }
    // moves value from register to memory (store)
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryWrite(ins) &&
        INS_OperandIsReg(ins, 1) && INS_OperandIsMemory(ins, 0)) {
        fprintf(trace, "\n%s\n", (INS_Disassemble(ins)).c_str());
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

    INS_AddInstrumentFunction(EmulateLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
