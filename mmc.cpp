#include "pin.H"
#include <stdio.h>
#include <map>

// A big table for memory
map<size_t, void *> memory;

// Initalize all objects

FILE *trace;

INT cacheInitializer(double cache_size, double line_size, size_t associativity,
                     size_t M) {
    if (associativity == DIRECT_MAPPED) {
        fprintf(trace, "Creating a Direct Mapped cache ");
    } else {
        fprintf(trace, "Creating a 2-way set associative cache ");
    }
    fprintf(trace,
            "of size %lfKB with line-size %lfB. Miss penalty, M, is %zu "
            "cycles.\n\n",
            cache_size, line_size, M);

    // Calculate and save some constants
    c = ((int)(log(cache_size) / log(2.0))) + 10;  // given in KB
    b = (int)(log(line_size) / log(2.0));
    s = (associativity == TWO_WAY_SET_ASSOC) ? c - b - 1 : c - b;
    S = 1 << s;  // number of sets
    fprintf(trace, "S = %d lines, c = %d bits, b = %d bits, s = %d bits\n\n", S,
            c, b, s);
    assoc = associativity;
    iL = (line_t **)malloc(S * sizeof(line_t *));
    dL = (line_t **)malloc(S * sizeof(line_t *));
    // Construct the caches
    for (int i = 0; i < S; i++) {
        iL[i] = (line_t *)calloc(1, sizeof(line_t));
        dL[i] = (line_t *)calloc(1, sizeof(line_t));
        // If two lines per set, then link the two line objects
        if (associativity == TWO_WAY_SET_ASSOC) {
            iL[i]->next = (line_t *)calloc(1, sizeof(line_t));
            dL[i]->next = (line_t *)calloc(1, sizeof(line_t));
        }
    }
    time_stamp = 0;
    return 0;
}

// Update stats about a cache item
VOID update_data_cache_elements(size_t addr, int type, bool miss) {
    std::map<size_t, cache_element_t *>::iterator itr =
        data_cache_elements.find(addr);
    cache_element_t *v;
    if (itr == data_cache_elements.end()) {
        v = (cache_element_t *)malloc(sizeof(cache_element_t));
        v->addr = addr;
        v->ins_type = type;
        v->num_references = 1;
        v->num_misses = miss ? 1 : 0;
        data_cache_elements.insert(make_pair(addr, v));
    } else {
        v = itr->second;
        v->num_references++;
        if (miss) {
            v->num_misses++;
        }
    }
}

// Update stats about a cache item
VOID update_ins_cache_elements(size_t addr, int type, bool miss) {
    std::map<size_t, cache_element_t *>::iterator itr =
        ins_cache_elements.find(addr);
    cache_element_t *v;
    if (itr == ins_cache_elements.end()) {
        v = (cache_element_t *)malloc(sizeof(cache_element_t));
        v->addr = addr;
        v->ins_type = type;
        v->num_references = 1;
        v->num_misses = miss ? 1 : 0;
        ins_cache_elements.insert(make_pair(addr, v));
    } else {
        v = itr->second;
        v->num_references++;
        if (miss) {
            v->num_misses++;
        }
    }
}

// Simulate cache behavior
VOID cacheRoutine(VOID *address, int type, line_t **L) {
    size_t val = (size_t)(address);
    size_t set_index = (val >> b) & ((1 << s) - 1);
    size_t tag = val >> (s + b);
    line_t *line = L[set_index];  // Line to look for data element in
    line_t *p = line;

    // Search to see if it's in the cache
    while (p != NULL) {
        if (p->tag == tag && p->valid) {
            // CACHE HIT
            p->LRU = time_stamp;
            if (type == INST) {
                update_ins_cache_elements(val, type, false);
            } else {
                update_data_cache_elements(val, type, false);
            }
            return;
        }
        p = p->next;
    }

    // CACHE MISS
    // before evicting, check if any are empty (valid == 0)
    p = line;
    bool found_empty = false;
    while (p != NULL) {
        if (p->valid == 0) {
            // Write this new value in
            p->tag = tag;
            p->LRU = time_stamp;
            p->valid = 1;
            found_empty = true;
            break;
        }
        p = p->next;
    }

    // Run this block if we ACTUALLY need to evict
    p = line;
    if (!found_empty) {
        // break down eviction policies
        if (assoc == TWO_WAY_SET_ASSOC) {
            // Use LRU eviction policy
            if (p->LRU > p->next->LRU) {
                p = p->next;
            }
        }
        p->tag = tag;
        p->LRU = time_stamp;
        p->valid = 1;
    }
    if (type == INST) {
        update_ins_cache_elements(val, type, true);
    } else {
        update_data_cache_elements(val, type, true);
    }
}

VOID callInsRoutine(VOID *ip) {
    time_stamp++;
    cacheRoutine(ip, INST, iL);
}

VOID callDataReadRoutine(VOID *addr) { cacheRoutine(addr, LOAD, dL); }
VOID callDataWriteRoutine(VOID *addr) { cacheRoutine(addr, STORE, dL); }

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v) {
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually
    // be
    // executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and
    // REP
    // prefixed instructions appear as predicated instructions in Pin.

    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Run cacheRoutine for Instruction cache
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)callInsRoutine,
                             IARG_INST_PTR, IARG_END);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            // Run cacheRoutine for Data (load) cache
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                     (AFUNPTR)callDataReadRoutine,
                                     IARG_MEMORYOP_EA, memOp, IARG_END);
        }
        // Note that in some architectures a single memory operand can
        // be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for
        // write.
        // Run cacheRoutine for Data (store) cache
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                     (AFUNPTR)callDataWriteRoutine,
                                     IARG_MEMORYOP_EA, memOp, IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    std::map<size_t, cache_element_t *>::iterator itr;
    fprintf(trace, "Printing out data cache\n");
    fprintf(trace,
            "PC     Type     References     Misses      Total Miss "
            "Cycles\n\n");
    cache_element_t *best;
    for (itr = data_cache_elements.begin(); itr != data_cache_elements.end();
         itr++) {
        best = itr->second;
        if (best->num_misses > 0) {
            fprintf(trace, "0x%zu         %zu      %zu      %zu\n", best->addr,
                    best->ins_type, best->num_references, best->num_misses);
        }
    }

    fprintf(trace, "\nPrinting out instruction cache\n");
    fprintf(trace, "PC         References     Misses\n\n");
    for (itr = data_cache_elements.begin(); itr != data_cache_elements.end();
         itr++) {
        best = itr->second;
        if (best->num_misses > 0) {
            fprintf(trace, "0x%zu            %zu      %zu\n", best->addr,
                    best->num_references, best->num_misses);
        }
    }

    // Free cache
    int i;
    for (i = 0; i < S; i++) {
        if (assoc == TWO_WAY_SET_ASSOC) {
            free(iL[i]->next);
            free(dL[i]->next);
        }
        free(iL[i]);
        free(dL[i]);
    }
    free(iL);
    free(dL);

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

    cacheInitializer(8, 64, DIRECT_MAPPED, 100);

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
