/*
 * Copyright (c) 2017 Carter Yagemann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <config.h>
#include <trace.h>
#include <monitor.h>
#include <output.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

#define HIGH_ADDR_MARK 0x70000000
#define KERNEL_MARK    (1UL << 63)

#define GFN_SHIFT(paddr) ((paddr) >> 12)
#define PADDR_SHIFT(gfn) ((gfn) << 12)

//Globals
addr_t max_paddr;
bool page_table_monitor_init;
vmi_event_t page_table_monitor_event;
vmi_event_t page_table_monitor_ss;
vmi_event_t page_table_monitor_cr3;
GHashTable *trapped_pages;     // key: addr_t, value: page_attr_t
GHashTable *cr3_to_pid;        // key: reg_t, value: vmi_pid_t
GHashTable *prev_vma;          // key: vmi_pid_t, value: prev_vma_t
GHashTable *vmi_events_by_pid; // key: vmi_pid_t, value: pid_events_t
GSList *pending_page_rescan;   // queue of table rescans
GSList *pending_page_retrap;   // queue of userspace retraps
GSList *cr3_callbacks;         // list of CR3 write callbacks
//stuff for watching ntdll physical pages
GHashTable *ntdll_pa_pages = NULL; // key: addr_t as paddr not gfn, value: page_info_t*

void process_pending_rescan(gpointer data, gpointer user_data);

int check_prev_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, addr_t vaddr, addr_t paddr)
{
    mem_seg_t vma = vmi_current_find_segment(vmi, event, vaddr);
    prev_vma_t *p_vma;

    if (!vma.size)
    {
        log_info("WARNING: Monitor - Could not find VMA for virtual address 0x%lx", vaddr);
        return 1;
    }

    // Heuristic - Packers like to unpack and execute dummy layers/waves to throw off unpacking tools.
    // For easy ones like what ASPack uses, we can try to read the whole VMA into a buffer and see how
    // many bytes are actually read. If it's 1 page (4KB) or less, it's probably not the real program.
    size_t dump_size;
    char *buffer = (char *) malloc(vma.size);
    vmi_read_va(vmi, vma.base_va, pid, vma.size, buffer, &dump_size);
    free(buffer);
    if (dump_size <= 0x1000)
        return 0;

    p_vma = (prev_vma_t *) g_hash_table_lookup(prev_vma, &pid);
    if (p_vma == NULL)
    {
        vmi_pid_t *pid_new = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
        prev_vma_t *vma_new = (prev_vma_t *) malloc(sizeof(prev_vma_t));
        *pid_new = pid;
        vma_new->vma.base_va = vma.base_va;
        vma_new->vma.size = vma.size;
        vma_new->paddr = paddr;
        g_hash_table_insert(prev_vma, pid_new, vma_new);
        return 1;
    }

    if (vma.base_va == p_vma->vma.base_va && vma.size == p_vma->vma.size)
        return 0;

    p_vma->vma.base_va = vma.base_va;
    p_vma->vma.size = vma.size;

    return 1;
}

static inline int addr_in_range(addr_t suspect, addr_t start, size_t size)
{
  return (suspect >= start && suspect < (start + size));
}

static inline int rip_in_page(addr_t rip, addr_t vaddr, page_cat_t cat)
{
    size_t size = 0;
    addr_t page = vaddr & VMI_BIT_MASK(12, 63);
    switch (cat)
    {
        case PAGE_CAT_NOT_SET:
        case PAGE_CAT_PML4:
        case PAGE_CAT_PDPT:
        case PAGE_CAT_PD:
        case PAGE_CAT_PT:
            return 0; // userspace instructions cannot be in pagetable or unknown pages
            break;
        case PAGE_CAT_4KB_FRAME:
            size = 4 * 1024;
            break;
        case PAGE_CAT_2MB_FRAME:
            size = 2 * 1024 * 1024;
            break;
        case PAGE_CAT_1GB_FRAME:
            size = 1 * 1024 * 1024 * 1024;
            break;
    }
    return addr_in_range(rip, page, size);
}

static inline int addr_in_imagebase(addr_t suspect, pid_events_t *pe)
{
    return addr_in_range(suspect, pe->vad_pe_start, pe->vad_pe_size);
}

#define swap_access(acc,wanted) \
    ((wanted & VMI_MEMACCESS_W) \
         ? ((acc & ~VMI_MEMACCESS_X) | VMI_MEMACCESS_W) \
         : ((acc & ~VMI_MEMACCESS_W) | VMI_MEMACCESS_X) \
    )

void update_access_map(pid_events_t *pe, addr_t vaddr,
        addr_t paddr, vmi_mem_access_t access_wanted)
{
    int need_insert = 0;
    vmi_mem_access_t access = (vmi_mem_access_t)(long)
        g_hash_table_lookup(pe->access_map, GINT_TO_POINTER(paddr));
    if (!access)
        log_debug("paddr=0x%lx (vaddr=0x%lx) not in access_map. adding...",
                paddr, vaddr);
    if ( !(access & access_wanted) )
    {
        access = swap_access(access, access_wanted);
        need_insert = 1;
    }
    if (!(access & VMI_MEMACCESS_W2X) && addr_in_imagebase(vaddr, pe))
    {
        access |= VMI_MEMACCESS_W2X;
        need_insert = 1;
    }
    if (need_insert)
        g_hash_table_insert(pe->access_map,
                GINT_TO_POINTER(paddr), GINT_TO_POINTER(access));
}

// maintain global trapped_pages hash and set memory traps
void monitor_set_trap(vmi_instance_t vmi, addr_t paddr, vmi_mem_access_t access,
                      vmi_pid_t pid, page_cat_t cat, addr_t vaddr)
{
    pid_events_t *pid_event = NULL;
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);

    if (!trap)
    {
        if (pid != 0)
            pid_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
        if (pid_event &&
                !(pid_event->flags & MONITOR_HIGH_ADDRS) &&
                vaddr > 4096 &&
                !addr_in_range(vaddr, pid_event->vad_pe_start, pid_event->vad_pe_size))
        {
            return;
        }
        trap = g_slice_new(trapped_page_t);
        trap->pid = pid;
        trap->cat = cat;
        g_hash_table_insert(trapped_pages, (gpointer)paddr, trap);
        vmi_set_mem_event(vmi, GFN_SHIFT(paddr), access, 0);
        if (pid_event)
            update_access_map(pid_event, vaddr, paddr, access);
        trace_trap("trace_trap paddr=0x%lx vaddr=0x%lx pid=%d cat=%s access=%s mesg=%s",
            paddr, vaddr, pid, cat2str(cat), access2str(access), "new trap");
    }
    //always update vaddr
    trap->vaddr = vaddr;
}

// remove entries from global trapped_pages hash and remove memory traps
void monitor_unset_trap(vmi_instance_t vmi, addr_t paddr)
{
    vmi_set_mem_event(vmi, GFN_SHIFT(paddr), VMI_MEMACCESS_N, 0);
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);
    if (trap)
    {
        pid_events_t *my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(trap->pid));
        if (my_pid_events)
            g_hash_table_remove(my_pid_events->access_map, GINT_TO_POINTER(paddr));
    }
    g_hash_table_remove(trapped_pages, (gpointer)paddr);
}

static inline pending_rescan_t *make_rescan(addr_t paddr, addr_t vaddr, vmi_pid_t pid, page_cat_t cat)
{
    pending_rescan_t *pending = (pending_rescan_t *) malloc(sizeof(pending_rescan_t));
    pending->paddr = paddr;
    pending->vaddr = vaddr;
    pending->pid   = pid;
    pending->cat   = cat;
    pending->access = VMI_MEMACCESS_INVALID;
    return pending;
}

static inline pending_rescan_t *make_retrap(addr_t paddr, addr_t vaddr, vmi_pid_t pid, page_cat_t cat, vmi_mem_access_t access)
{
    pending_rescan_t *pending = make_rescan(paddr, vaddr, pid, cat);
    pending->access = access;
    return pending;
}

// untrap page and schedule a retrap for later, most likely at cr3 change
void untrap_and_schedule_retrap(vmi_instance_t vmi, GSList *list, pending_rescan_t *page)
{
    monitor_unset_trap(vmi, page->paddr);
    list = g_slist_prepend(list, page);
}

// called in monitor_handler_cr3 to retrap any pages scheduled for retrapping
event_response_t cr3_retrap(vmi_instance_t vmi, vmi_event_t *event)
{
    foreach_data_t cb_data;
    if (pending_page_retrap)
    {
        cb_data.vmi = vmi;
        cb_data.list = &pending_page_retrap;
        g_slist_foreach(pending_page_retrap, process_pending_rescan, &cb_data);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

// called in monitor_trap_vma to trap after a write trap.
// this is needed when an instruction writes to the page that it is in.
event_response_t write_retrap(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_X, 0);
    return VMI_EVENT_RESPONSE_NONE;
}

// called in monitor_untrap_vma to trap after an exec trap.
// this is needed when an instruction writes to the page that it is in.
event_response_t exec_retrap(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_W, 0);
    return VMI_EVENT_RESPONSE_NONE;
}

// after a page that has been written to has also been executed,
// we "untrap" it by setting all pages in that VMA back to VMI_MEMACCESS_N
void monitor_untrap_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    pid_events_t *my_pid_events;
    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    addr_t vaddr = event->mem_event.gla;

    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (!my_pid_events)
    {
        log_info("WARNING: monitor_untrap_vma - Could not find PID %d", pid);
        return;
    }
    update_access_map(my_pid_events, vaddr, paddr, VMI_MEMACCESS_W);
    trace_untrap_vma("pid=%d, paddr=0x%lx, vaddr=0x%lx",
            pid, paddr, vaddr);
    page_cat_t cat = PAGE_CAT_4KB_FRAME;
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);
    if (trap)
      cat = trap->cat;
    // if an instruction writes to the page that it is in,
    // step past it then put the VMI_MEMACCESS_W on the page
    if (rip_in_page(event->x86_regs->rip, vaddr, cat))
    {
      trace_untrap_vma("removing X: rip(0x%lx) is in page(0x%lx) cat=%s",
          event->x86_regs->rip, vaddr, cat2str(cat));
      vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
      vmi_step_event(vmi, event, event->vcpu_id, 1, exec_retrap);
    }
    else
    {
      trace_untrap_vma("removing X: pid=%d, paddr=0x%lx, vaddr=0x%lx", pid, paddr, vaddr);
      vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_W, 0);
    }
}

// a page belonging to the PID has been written to. place an
// "execute" trap on that page with VMI_MEMACCESS_X
void monitor_trap_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    addr_t vaddr = event->mem_event.gla;
    if (vaddr >= KERNEL_MARK)
    {
        log_info("WARNING: monitor_trap_vma - Tried to trap kernel pages, request ignored");
        return;
    }
    pid_events_t *my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (my_pid_events)
    {
        update_access_map(my_pid_events, vaddr, paddr, VMI_MEMACCESS_X);
        trace_exec_trap(
                "trace_exec_trap:pid=%d paddr=0x%lx vaddr=0x%lx"
                " mesg:UPDATE access_map for pid: rip=0x%lx",
                pid, paddr, vaddr,
                event->x86_regs->rip);
        page_cat_t cat = PAGE_CAT_4KB_FRAME;
        trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);
        if (trap)
          cat = trap->cat;
        // if an instruction writes to the page that it is in,
        // step past it then put the VMI_MEMACCESS_X on the page
        if (rip_in_page(event->x86_regs->rip, vaddr, cat))
        {
          trace_trap_vma("adding X: rip(0x%lx) is in page(0x%lx) cat=%s",
              event->x86_regs->rip, vaddr, cat2str(cat));
          vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
          vmi_step_event(vmi, event, event->vcpu_id, 1, write_retrap);
        }
        else
          vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_X, 0);
    }
}

void destroy_trapped_page(gpointer val) { g_slice_free(trapped_page_t, val); }

//called by g_hash_table_destroy() when g_hash_table_new_full() is used
void destroy_watched_pid(gpointer data)
{
    pid_events_t *val = (pid_events_t *)data;
    g_hash_table_destroy(val->access_map);
    free(val->process_name);
    if (val->vadinfo_bundles) g_ptr_array_unref(val->vadinfo_bundles);
    g_slice_free(pid_events_t, val);
}

pid_events_t *add_new_pid(vmi_pid_t pid)
{
    pid_events_t *pval = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (pval)
        //skip if the pid already exists
        return pval;
    pval = g_slice_new(pid_events_t);
    pval->pid = pid;
    pval->access_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(vmi_events_by_pid, GINT_TO_POINTER(pid), pval);
    pval->process_name = NULL;
    pval->vadinfo_bundles = NULL;
    pval->vad_pe_index = -1;
    pval->vad_pe_start = HIGH_ADDR_MARK;
    pval->vad_pe_size = 0;
    pval->has_run_once = 0;
    return pval;
}

void monitor_trap_pt(vmi_instance_t vmi, addr_t pt, vmi_pid_t pid, addr_t pd_vaddr)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;
    addr_t vaddr;

    monitor_set_trap(vmi, pt, VMI_MEMACCESS_W, pid, PAGE_CAT_PT, 0);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vaddr = pd_vaddr | (((addr_t)index) << 12);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_WRITABLE(entry_val) && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_4KB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_4KB_FRAME, vaddr);
            continue;
        }
    }
}

void monitor_trap_pd(vmi_instance_t vmi, addr_t pd, vmi_pid_t pid, addr_t pdpt_vaddr)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;
    addr_t vaddr;

    monitor_set_trap(vmi, pd, VMI_MEMACCESS_W, pid, PAGE_CAT_PD, 0);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pd + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vaddr = pdpt_vaddr | (((addr_t)index) << 21);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_2MB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_2MB_FRAME, vaddr);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PT_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pt(vmi, next_addr, pid, vaddr);
            continue;
        }
    }
}

void monitor_trap_pdpt(vmi_instance_t vmi, addr_t pdpt, vmi_pid_t pid, addr_t pml4_vaddr)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;
    addr_t vaddr;

    monitor_set_trap(vmi, pdpt, VMI_MEMACCESS_W, pid, PAGE_CAT_PDPT, 0);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pdpt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vaddr = pml4_vaddr | (((addr_t)index) << 30);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_1GB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_1GB_FRAME, vaddr);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PD_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pd(vmi, next_addr, pid, vaddr);
            continue;
        }
    }
}

void monitor_trap_pml4(vmi_instance_t vmi, addr_t pml4, vmi_pid_t pid)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;
    addr_t vaddr;

    monitor_set_trap(vmi, pml4, VMI_MEMACCESS_W, pid, PAGE_CAT_PML4, 0);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pml4 + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vaddr = (((addr_t)index) << 39);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        next_addr = PAGING_INTEL_64_GET_PDPT_PADDR(entry_val);
        if (next_addr <= max_paddr)
            monitor_trap_pdpt(vmi, next_addr, pid, vaddr);
    }
}

void monitor_trap_table(vmi_instance_t vmi, pid_events_t *pid_event)
{
    addr_t dtb = PAGING_INTEL_64_GET_PML4_PADDR(pid_event->cr3);

    if (pid_event->pid == 0)
    {
        log_error("ERROR: Monitor - Trapping PID 0 is not allowed");
        return;
    }

    if (dtb == 0)
    {
        log_error("ERROR: Monitor - Failed to find DTB for PID %d", pid_event->pid);
        return;
    }

    monitor_trap_pml4(vmi, dtb, pid_event->pid);
}

void queue_pending_rescan(addr_t paddr, addr_t vaddr, vmi_pid_t pid, page_cat_t cat, GSList **list)
{
    pending_rescan_t *pending = make_rescan(paddr, vaddr, pid, cat);
    *list = g_slist_prepend(*list, pending);
}

void process_pending_rescan(gpointer data, gpointer user_data)
{
    pending_rescan_t *rescan = (pending_rescan_t *) data;
    foreach_data_t *rescan_data = (foreach_data_t *) user_data;
    vmi_instance_t vmi = rescan_data->vmi;
    addr_t vaddr = rescan->vaddr;
    addr_t index;

    //log_info("paddr=0x%lx pid=%d cat=%s",
    //        rescan->paddr, rescan->pid, cat2str(rescan->cat));
    const page_cat_t cat = rescan->cat;
    switch (cat)
    {
        case PAGE_CAT_PML4:
            monitor_trap_pml4(vmi, rescan->paddr, rescan->pid);
            break;
        case PAGE_CAT_PDPT:
            index = vaddr & VMI_BIT_MASK(39, 47);
            monitor_trap_pdpt(vmi, rescan->paddr, rescan->pid, index);
            break;
        case PAGE_CAT_PD:
            index = vaddr & VMI_BIT_MASK(30, 47);
            monitor_trap_pd(vmi, rescan->paddr, rescan->pid, index);
            break;
        case PAGE_CAT_PT:
            index = vaddr & VMI_BIT_MASK(21, 47);
            monitor_trap_pt(vmi, rescan->paddr, rescan->pid, index);
            break;
        case PAGE_CAT_4KB_FRAME:
        case PAGE_CAT_2MB_FRAME:
        case PAGE_CAT_1GB_FRAME:
            monitor_set_trap(vmi, rescan->paddr, rescan->access, rescan->pid, cat, vaddr);
            break;
        case PAGE_CAT_NOT_SET:
            break;
    }

    *rescan_data->list = g_slist_remove(*rescan_data->list, data);
    free(data);
}

//walk through vadinfo bundles to re-create
int build_userspace_page_maps(vmi_instance_t vmi, pid_events_t *pid_event,
	GHashTable* map)
{
    int added = 0;
    if (my_assert((pid_event->vad_pe_index == -1),
		make_static_mesg("vad_pe_index == -1")))
        goto out;
    vadinfo_bundle_t *current_bundle = g_ptr_array_index(pid_event->vadinfo_bundles, pid_event->vad_pe_index);
    if (my_assert(!current_bundle,
		make_static_mesg("current_bundle is NULL")))
        goto out;
    GPtrArray *vad_maps = current_bundle->vadinfo_maps;
    if (my_assert(!vad_maps,
		make_static_mesg("vad_maps is NULL")))
        goto out;
    GHashTable *vad_map;
    for (guint i = 0; i < vad_maps->len; ++i)
    {
        vad_map = g_ptr_array_index(vad_maps, i);
        page_info_t *info;
        ulong _pagesize = VMI_PS_4KB; //safe default
        addr_t addr = 0;
        addr_t start = (addr_t)json_node_get_int(g_hash_table_lookup(vad_map, "Start"));
		if (start != pid_event->vad_pe_start)
			continue;
        addr_t end = (addr_t)json_node_get_int(g_hash_table_lookup(vad_map, "End"));
        trace_ntdll("building userspace: start=0x%lx end=0x%lx pid=%d fnwd={%s}",
                start, end, pid_event->pid,
                json_node_get_string(g_hash_table_lookup(vad_map, "FileNameWithDevice"))
                );

        for (addr = start; addr <= end; addr += _pagesize)
        {
            //info is stored in three hash tables. but should only be freed once
            info = g_slice_new0(page_info_t);
            if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, pid_event->cr3, addr, info))
            {
                //page is not yet present, but we still need the page size
                if (info->x86_ia32e.pte_location) _pagesize = VMI_PS_4KB;
                else if (info->x86_ia32e.pgd_location) _pagesize = VMI_PS_2MB;
                else /*if (info->x86_ia32e.pdpte_location)*/ _pagesize = VMI_PS_1GB;
                trace_ntdll_debug2("page is not yet present: vaddr=0x%lx size=0x%lx", addr, _pagesize);
                g_slice_free(page_info_t, info);
            }
            else
            {
                _pagesize = info->size;
                gpointer key = GINT_TO_POINTER(info->paddr);
                if (!g_hash_table_contains(map, key))
                {
                    trace_ntdll_debug1("adding imagebase address: paddr=0x%lx pid=%d fnwd={%s}",
                            info->paddr, pid_event->pid,
                            json_node_get_string(g_hash_table_lookup(vad_map, "FileNameWithDevice"))
                            );
                    g_hash_table_insert(map, key, info);
                    added++;
                }
            }
        }
    }
    trace_ntdll("done building userspace: pid=%d", pid_event->pid);
out:
    return added;
}

void trap_ntdll(vmi_instance_t vmi)
{
    trace_ntdll("starting trap of ntdll");
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, ntdll_pa_pages);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        page_info_t *info = (page_info_t*)value;
        page_cat_t cat;
        switch (info->size)
        {
            default:
            case VMI_PS_4KB:
                cat = PAGE_CAT_4KB_FRAME;
                break;
            case VMI_PS_2MB:
                cat = PAGE_CAT_2MB_FRAME;
                break;
            case VMI_PS_1GB:
                cat = PAGE_CAT_1GB_FRAME;
                break;
        }
        trace_ntdll_debug1("setting trap: paddr=0x%lx cat=%s",
                info->paddr, cat2str(cat));
        monitor_set_trap(vmi, info->paddr, VMI_MEMACCESS_X, 0, cat, 0);
    }
    trace_ntdll("finished trap of ntdll");
}

void destroy_pageinfo(gpointer val) { g_slice_free(page_info_t, val); }

gboolean watch_ntdll(vmi_instance_t vmi)
{
    if (ntdll_pa_pages && g_hash_table_size(ntdll_pa_pages) > 0)
    {
        trace_ntdll_debug1("ntdll_pa_pages is already setup");
        return 1;
    }
    //setup ntdll_pa_pages as empty since its safe to
    //call g_hash_table_contains() even if empty
    ntdll_pa_pages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_pageinfo);

    GHashTableIter iter;
    gpointer key, value;
    const char *magic_name = "ntdll.dll"; //used to find vad for ntdll.dll

    GHashTable *all_pids = vmi_get_all_pids(vmi);
    g_hash_table_iter_init(&iter, all_pids);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        vmi_pid_t magic_pid = GPOINTER_TO_INT(key);
        //do not scan any pid that we intentionally added
        if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(magic_pid)))
            continue;
        trace_ntdll("scanning ntdll from pid=%d", magic_pid);
        pid_events_t *cur_pid = add_new_pid(magic_pid);
        g_hash_table_steal(vmi_events_by_pid, GINT_TO_POINTER(magic_pid));
        cur_pid->process_name = calloc(1, strlen(magic_name)+1);
        strcpy(cur_pid->process_name, magic_name);
        vmi_pid_to_dtb(vmi, magic_pid, &cur_pid->cr3);
        volatility_vadinfo(magic_pid, global.volatility_cmd_prefix, dump_count);
        if (find_process_in_vads(vmi, cur_pid, dump_count)) {
            vadinfo_bundle_t *bundle = g_ptr_array_index(cur_pid->vadinfo_bundles, dump_count);
            cur_pid->vad_pe_index = bundle->pe_index;
            __attribute__((unused))
            int added = build_userspace_page_maps(vmi, cur_pid, ntdll_pa_pages);
            trace_ntdll("found %d pages in pid=%d, total=%u",
                    added, magic_pid, g_hash_table_size(ntdll_pa_pages));
        }
        trace_ntdll("done scanning ntdll from pid=%d", magic_pid);
        delete_vadinfo_json(magic_pid, dump_count);
        destroy_watched_pid(cur_pid);
        if (g_hash_table_size(ntdll_pa_pages) >= 200)
            break;
    }
    g_hash_table_destroy(all_pids);
    if (ntdll_pa_pages && g_hash_table_size(ntdll_pa_pages) > 0)
    {
        trap_ntdll(vmi);
        return 1;
    }
    return 0;
}

void destroy_ntdll(void)
{
    if (ntdll_pa_pages)
        g_hash_table_destroy(ntdll_pa_pages);
}

void cr3_callback_dispatcher(gpointer cb, gpointer user_data)
{
    foreach_data_t *cb_data = (foreach_data_t *) user_data;
    vmi_instance_t vmi = cb_data->vmi;
    vmi_event_t *event = cb_data->event;
    ((event_callback_t)cb)(vmi, event);
}

void remove_dead_pid(gpointer data, gpointer user_data)
{
    vmi_pid_t dead_pid = GPOINTER_TO_INT(data);
    foreach_data_t *cb_data = (foreach_data_t *) user_data;
    vmi_instance_t vmi = cb_data->vmi;
    monitor_remove_page_table(vmi, dead_pid);
    *cb_data->list = g_slist_remove(*cb_data->list, data);
}

void print_events_by_pid(void)
{
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vmi_events_by_pid);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        vmi_pid_t pid = GPOINTER_TO_INT(key);
        pid_events_t *pid_event = value;
        log_info("events_by_pid, pid=%d cr3=0x%lx", pid, pid_event->cr3);
    }
}

void print_cr3_to_pid(void)
{
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, cr3_to_pid);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        reg_t cr3 = (long)key;
        vmi_pid_t pid = GPOINTER_TO_INT(value);
        log_info("cr3_to_pid, pid=%d cr3=0x%lx", pid, cr3);
    }
}

void vmi_list_all_processes_windows(vmi_instance_t vmi, vmi_event_t *event);
event_response_t monitor_handler_cr3(vmi_instance_t vmi, vmi_event_t *event)
{
    //bail out right away if monitoring is not started or is now off
    if (!page_table_monitor_init)
        return VMI_EVENT_RESPONSE_NONE;

    // If there are any registered callbacks, invoke them
    foreach_data_t cb_data;
    cb_data.vmi = vmi;
    cb_data.event = event;
    cb_data.list = &cr3_callbacks;
    g_slist_foreach(cr3_callbacks, cr3_callback_dispatcher, &cb_data);

    vmi_pid_t pid = vmi_current_pid(vmi, event);
    pid_events_t *pid_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    reg_t evt_cr3 = event->x86_regs->cr3;

    //bail out right away if the cr3 is one that we track
    if (g_hash_table_contains(cr3_to_pid, (gpointer)evt_cr3))
    {
        vmi_pid_t cr3_pid = GPOINTER_TO_INT(g_hash_table_lookup(cr3_to_pid, (gpointer)evt_cr3));
        //but before we bail, trap its page table once it executes the first time
        if (cr3_pid == 0)
        {
            if (pid_event)
            {
                watch_ntdll(vmi);
                g_hash_table_insert(cr3_to_pid, (gpointer)evt_cr3, GINT_TO_POINTER(pid));
                if (!pid_event->process_name)
                {
                    pid_event->process_name = vmi_current_name(vmi, event);
                    log_info("pid=%d eprocess=0x%lx name={%s}",
                            pid, pid_event->eprocess, pid_event->process_name);
                }
                volatility_vadinfo(pid, global.volatility_cmd_prefix, dump_count);
                if (pid_event->pid != pid) //data structure bugfix
                    pid_event->pid = pid;
                if (find_process_in_vads(vmi, pid_event, dump_count)) {
                  vadinfo_bundle_t *bundle = g_ptr_array_index(pid_event->vadinfo_bundles, dump_count);
                  log_debug("pid=%d pe_index=%d", pid, bundle->pe_index);
                  //if (bundle->parsed_pe)
                  //  show_parsed_pe(bundle->parsed_pe);
                }
                delete_vadinfo_json(pid_event->pid, dump_count);
                dump_count++;
            }
            else
            {
                //print_events_by_pid();
                //print_cr3_to_pid();
                //vmi_list_all_processes_windows(vmi, event);
            }
        }
        return VMI_EVENT_RESPONSE_NONE;
    }

    //bail out right away if we already track this PID
    if (pid_event)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    // This process isn't being tracked. If its parent is a process that *is* being tracked, check
    // if the callback for that process wants to follow children and if so, register it.
    vmi_pid_t parent_pid = vmi_current_parent_pid(vmi, event);
    pid_events_t *parent_cb_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(parent_pid));

    if (parent_cb_event != NULL && (parent_cb_event->flags & MONITOR_FOLLOW_CHILDREN))
    {
        monitor_add_page_table(vmi, pid, parent_cb_event->cb, parent_cb_event->flags, 0);
        log_info("FOUND CHILD: PID %d", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Iterater over `vmi_events_by_pid` and check if any of our
    // watched processes have exited. If so, remove them.

    GHashTable *all_pids = vmi_get_all_pids(vmi);
    if (!all_pids)
        return VMI_EVENT_RESPONSE_NONE;
    GHashTableIter iter;
    gpointer key, value;
    GSList *dead_pids = NULL;
    g_hash_table_iter_init(&iter, vmi_events_by_pid);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        vmi_pid_t pid_k = GPOINTER_TO_INT(key);
        if (!g_hash_table_contains(all_pids, key))
        {
            dead_pids = g_slist_prepend(dead_pids, key);
            log_info("REMOVED DEAD PROCESS: %d", pid_k);
        }
    }
    g_hash_table_destroy(all_pids);
    if (dead_pids)
    {
        foreach_data_t cb_data;
        cb_data.vmi = vmi;
        cb_data.list = &dead_pids;
        g_slist_foreach(dead_pids, remove_dead_pid, &cb_data);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t monitor_handler_ss(vmi_instance_t vmi, vmi_event_t *event)
{
    foreach_data_t rescan_data;
    rescan_data.vmi = vmi;
    rescan_data.event = event;
    rescan_data.list = &pending_page_rescan;
    g_slist_foreach(pending_page_rescan, process_pending_rescan, &rescan_data);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t monitor_handler(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pid_t pid;
    pid_events_t *my_pid_events;
    const size_t len = 80;
    char mesg[len];
    char *curr_name;

    //bail out right away if monitoring is not started or is now off
    if (!page_table_monitor_init)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    addr_t vaddr = event->mem_event.gla;
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);

    if (trap == NULL)
    {
        log_info("WARNING: Monitor - Failed to find PID for physical address 0x%lx", paddr);
        trace_trap("trace_trap paddr=0x%lx vaddr=0x%lx : trap not found", paddr, vaddr);
        monitor_unset_trap(vmi, paddr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    pid = trap->pid;
    vmi_pid_t curr_pid = vmi_current_pid(vmi, event);
    if (pid == 0) // pid=0 means its part of ntdll
        pid = curr_pid;

    //printf("monitor_handler:recv_event rip=%p paddr=%p cat=%s access=%s curr_pid=%d",
    //    (void *) event->x86_regs->rip, (void *) paddr, cat2str(trap->cat), access2str(event), curr_pid);

    // If the PID of the current process is not equal to the PID retrieved from trapped_pages, then:
    // 1, a system process is changing our PIDs pagetable. ignore.
    // 2, its an execve() and our PID is being replaced. update trap->pid.
    // 3, since we dont keep track of when our PIDs pagetable shrinks, its possible
    //    that the page belongs to some other PID and not us. forget the page.
    // 5, some other PID that we dont track accessed, write or exec, a userspace page that
    //    our PID currently has in its pagetable. WTF!
    // 6, trapped_pages had the page, but we dont care about it. forget the page.
    if (curr_pid != pid && !is_pagetable_page(trap->cat))
    {
        if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(curr_pid)))
        {
            curr_name = vmi_current_name(vmi, event);
            snprintf(mesg, len - 1, "=pid_change curr_name=%s curr_pid=%d access=%s",
                     curr_name, curr_pid, access2str(event->mem_event.out_access));
            free(curr_name);
            trace_trap("trace_trap paddr=0x%lx vaddr=0x%lx pid=%d cat=%s mesg=%s",
                paddr, vaddr, pid, cat2str(trap->cat), mesg);
            pid = trap->pid = curr_pid;
        }
        else
        {
            //it is possible that the PID we are watching no longer has this page anymore
            my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
            if (my_pid_events)
            {
                addr_t page;
                vmi_v2pcache_flush(vmi, my_pid_events->cr3);
                status_t s = vmi_pagetable_lookup(vmi, my_pid_events->cr3, vaddr, &page);
                if (s != VMI_SUCCESS)
                {
                    //our PID no longer has this page
                    monitor_unset_trap(vmi, paddr);
                    return VMI_EVENT_RESPONSE_NONE;
                }
                else
                {
                    //our PID has this page and some other PID accessed it as W or X
                    curr_name = vmi_current_name(vmi, event);
                    snprintf(mesg, len - 1, "=unknown_pid curr_name=%s curr_pid=%d access=%s",
                             curr_name, curr_pid, access2str(event->mem_event.out_access));
                    free(curr_name);
                    trace_trap("trace_trap paddr=0x%lx vaddr=0x%lx pid=%d cat=%s mesg=%s",
                        paddr, vaddr, pid, cat2str(trap->cat), mesg);
                    pending_rescan_t *retrap = make_retrap(paddr, vaddr, pid, trap->cat, event->mem_event.out_access);
                    untrap_and_schedule_retrap(vmi, pending_page_retrap, retrap);
                    return VMI_EVENT_RESPONSE_NONE;
                }
            }
            else
            {
                //trapped_pages has this page, but we dont care about it. forget it.
                trace_trap("trace_trap paddr=0x%lx vaddr=0x%lx pid=%d cat=%s mesg=%s",
                    paddr, vaddr, pid, cat2str(trap->cat), "forget this");
                monitor_unset_trap(vmi, paddr);
                return VMI_EVENT_RESPONSE_NONE;
            }
        }
    }

    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (my_pid_events == NULL)
    {
        if (trap->pid == 0)
        {
            pending_rescan_t *retrap = make_retrap(paddr, vaddr, trap->pid, trap->cat, event->mem_event.out_access);
            untrap_and_schedule_retrap(vmi, pending_page_retrap, retrap);
        }
        else
        {
            log_info("WARNING: Monitor - Failed to find callback event for PID %d", pid);
            monitor_unset_trap(vmi, paddr);
        }
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (is_userspace_page(trap->cat))
    {
        if (event->mem_event.out_access & VMI_MEMACCESS_X)
        {
            if (ntdll_pa_pages
                    && g_hash_table_contains(ntdll_pa_pages, GINT_TO_POINTER(paddr)))
            {
                trace_ntdll("exec in ntdll by pid=%d", pid);
                if (!my_pid_events->has_run_once)
                {
                    my_pid_events->has_run_once = 1;
                    trace_ntdll("exec in ntdll by pid=%d, trapping table", pid);
                    monitor_trap_table(vmi, my_pid_events);
                }
                pending_rescan_t *retrap = make_retrap(paddr, vaddr, pid, trap->cat, event->mem_event.out_access);
                untrap_and_schedule_retrap(vmi, pending_page_retrap, retrap);
            }
            else
            {
                if ((my_pid_events->flags & MONITOR_HIGH_ADDRS) || vaddr < HIGH_ADDR_MARK)
                    if (addr_in_range(event->x86_regs->rip, my_pid_events->vad_pe_start, my_pid_events->vad_pe_size)
                        )
                        my_pid_events->cb(vmi, event, pid, trap->cat);
                    else { trace_exec("VMI_MEMACCESS_X: address not in range: rip=0x%lx", event->x86_regs->rip); }
                else { trace_exec("VMI_MEMACCESS_X: address not below HIGH_ADDR_MARK: rip=0x%lx", event->x86_regs->rip); }
                trace_exec("calling monitor_untrap_vma:VMI_MEMACCESS_X: rip=0x%lx", event->x86_regs->rip);
                monitor_untrap_vma(vmi, event, pid);
            }
        }
        else if (event->mem_event.out_access & VMI_MEMACCESS_W)
        {
            trace_write("calling monitor_trap_vma:VMI_MEMACCESS_W: rip=0x%lx", event->x86_regs->rip);
            monitor_trap_vma(vmi, event, pid);
        }
        else
        {
            log_info("WARNING: Monitor - Caught unexpected memory access %d", event->mem_event.out_access);
            monitor_unset_trap(vmi, paddr);
        }
        return VMI_EVENT_RESPONSE_NONE;
    }
    else     // page in process's page table
    {
        //log_info("paddr=0x%lx pid=%d cat=%s access=%s curr_pid=%d",
        //    paddr, pid, cat2str(trap->cat), access2str(event), curr_pid);
        queue_pending_rescan(paddr, vaddr, pid, trap->cat, &pending_page_rescan);
        return (VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
    }
}

int monitor_init(vmi_instance_t vmi)
{
    if (vmi_get_page_mode(vmi, 0) != VMI_PM_IA32E)
    {
        log_error("ERROR: Monitor - Only IA-32e paging is supported at this time");
        page_table_monitor_init = 0;
        return 1;
    }

    trapped_pages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_trapped_page);
    cr3_to_pid = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    prev_vma = g_hash_table_new_full(g_int_hash, g_int_equal, free, free);
    vmi_events_by_pid = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                        NULL, destroy_watched_pid);
    pending_page_rescan = NULL;
    pending_page_retrap = NULL;
    cr3_callbacks = NULL;
    monitor_add_cr3(cr3_retrap);

    SETUP_MEM_EVENT(&page_table_monitor_event, 0, VMI_MEMACCESS_WX, monitor_handler, 1);
    if (vmi_register_event(vmi, &page_table_monitor_event) != VMI_SUCCESS)
    {
        log_error("ERROR: Monitor - Failed to register page table event");
        page_table_monitor_init = 0;
        return 1;
    }

    uint32_t vcpu_mask = (1U << vmi_get_num_vcpus(vmi)) - 1;
    SETUP_SINGLESTEP_EVENT(&page_table_monitor_ss, vcpu_mask, monitor_handler_ss, 1);
    if (vmi_register_event(vmi, &page_table_monitor_ss) != VMI_SUCCESS)
    {
        log_error("ERROR: Monitor - Failed to register single step event");
        vmi_clear_event(vmi, &page_table_monitor_event, NULL);
        page_table_monitor_init = 0;
        return 1;
    }

    SETUP_REG_EVENT(&page_table_monitor_cr3, CR3, VMI_REGACCESS_W, 0, monitor_handler_cr3);
    if (vmi_register_event(vmi, &page_table_monitor_cr3) != VMI_SUCCESS)
    {
        log_error("ERROR: Monitor - Failed to register CR3 monitoring event");
        vmi_clear_event(vmi, &page_table_monitor_event, NULL);
        vmi_clear_event(vmi, &page_table_monitor_ss, NULL);
        page_table_monitor_init = 0;
        return 1;
    }

    max_paddr = vmi_get_max_physical_address(vmi);

    page_table_monitor_init = 1;

    return 0;
}

void monitor_destroy(vmi_instance_t vmi)
{
    log_debug("monitor_destroy() called");
    if (!page_table_monitor_init)
        return;

    vmi_clear_event(vmi, &page_table_monitor_cr3, NULL);
    vmi_clear_event(vmi, &page_table_monitor_event, NULL);
    vmi_clear_event(vmi, &page_table_monitor_ss, NULL);
    log_debug("monitor_destroy() events cleared");

    g_hash_table_destroy(trapped_pages);
    g_hash_table_destroy(cr3_to_pid);
    g_hash_table_destroy(vmi_events_by_pid);
    g_slist_free_full(pending_page_rescan, free);
    g_slist_free_full(pending_page_retrap, free);
	destroy_ntdll();

    page_table_monitor_init = 0;
}

void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb, uint8_t flags, reg_t cr3)
{
    if (cb == NULL)
    {
        log_error("ERROR: Monitor - Must specify callback function, cannot be null.");
        return;
    }

    if (!page_table_monitor_init)
    {
        log_error("ERROR: Monitor - Not initialized, cannot add page table");
        return;
    }

    if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(pid)))
    {
        log_error("ERROR: Monitor - Callback already registered for PID %d", pid);
        return;
    }

    pid_events_t *pid_event = add_new_pid(pid);
    if (cr3 == 0)
    {
        vmi_pidcache_flush(vmi);
        if (vmi_pid_to_dtb(vmi, pid, &pid_event->cr3) == VMI_FAILURE)
        {
            g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));
            return;
        }
    }
    else pid_event->cr3 = cr3;
    pid_event->flags = flags;
    pid_event->cb = cb;
    pid_event->eprocess = vmi_get_process_by_cr3(vmi, pid_event->cr3);
    char *name = NULL;
    //set the pid to 0 as a flag that its page table has not been scanned yet
    //then delay trapping its page table until it first executes
    g_hash_table_insert(cr3_to_pid, (gpointer)pid_event->cr3, 0);
    trace("pid=%d cr3=0x%lx eprocess=0x%lx name={%s}",
            pid, pid_event->cr3, pid_event->eprocess,
            (name = vmi_get_eprocess_name(vmi, pid_event->eprocess))
         );
    if (name) free(name);

    //the table trap is delayed until:
    //    the pid is first seen in monitor_handler_cr3(), ntdll exec is trapped
    //    ntdll is executed by our pid, then trap the pagetable
}

void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid)
{
    pid_events_t *my_pid_events;

    if (!page_table_monitor_init)
    {
        log_error("ERROR: Monitor - Not initialized, cannot remove page table");
        return;
    }

    log_info("pid=%d", pid);
    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (my_pid_events)
    {
        //remove from cr3_to_pid before my_pid_events gets destroyed
        g_hash_table_remove(cr3_to_pid, (gpointer)my_pid_events->cr3);
        int i;
        //clear userspace traps
        guint num_pages = 0;
        //copy keys into array since we are altering the access_map
        gpointer *pages = g_hash_table_get_keys_as_array(
                my_pid_events->access_map, &num_pages);
        if (pages)
        {
            for (i = 0; i < num_pages; i++)
                monitor_unset_trap(vmi, (addr_t)pages[i]);
            g_free(pages);
        }
        g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));
    }
}

void monitor_add_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_prepend(cr3_callbacks, cb);
}

void monitor_remove_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_remove(cr3_callbacks, cb);
}
