/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_read(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    printf("Executing basic bloc: " TARGET_FMT_lx "\n", tb->pc);
    return 0;
}

int after_read(CPUState *cpu, target_ulong pc, target_ulong addr,
                                       target_ulong size, void *buf)
{
    printf("Memory read: PC=" TARGET_FMT_lx " addr=" TARGET_FMT_lx "\n",
            pc, addr);
    return 0;
}

bool init_plugin(void *self) {
    panda_enable_memcb();

    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.phys_mem_after_read = after_read;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);


    return true;
}

void uninit_plugin(void *self) { }
