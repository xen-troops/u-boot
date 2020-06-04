/*
 ****************************************************************************
 * (C) 2006 - Cambridge University
 * (C) 2020 - EPAM Systems Inc.
 ****************************************************************************
 *
 *        File: gnttab.c
 *      Author: Steven Smith (sos22@cam.ac.uk)
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *
 *        Date: July 2006
 *
 * Environment: Xen Minimal OS
 * Description: Simple grant tables implementation. About as stupid as it's
 *  possible to be and still work.
 *
 ****************************************************************************
 */
#include <common.h>
#include <linux/compiler.h>
#include <log.h>
#include <malloc.h>

#include <asm/armv8/mmu.h>
#include <asm/io.h>
#include <asm/xen/system.h>

#include <linux/bug.h>

#include <xen/gnttab.h>
#include <xen/hvm.h>

#include <xen/interface/memory.h>

#define NR_RESERVED_ENTRIES 8

/* NR_GRANT_FRAMES must be less than or equal to that configured in Xen */
#define NR_GRANT_FRAMES 1
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(struct grant_entry_v1))

static struct grant_entry_v1 *gnttab_table;
static grant_ref_t gnttab_list[NR_GRANT_ENTRIES];

static void put_free_entry(grant_ref_t ref)
{
    unsigned long flags;
    local_irq_save(flags);
    gnttab_list[ref] = gnttab_list[0];
    gnttab_list[0]  = ref;
    local_irq_restore(flags);
}

static grant_ref_t get_free_entry(void)
{
    unsigned int ref;
    unsigned long flags;
    local_irq_save(flags);
    ref = gnttab_list[0];
    BUG_ON(ref < NR_RESERVED_ENTRIES || ref >= NR_GRANT_ENTRIES);
    gnttab_list[0] = gnttab_list[ref];
    local_irq_restore(flags);
    return ref;
}

grant_ref_t gnttab_grant_access(domid_t domid, unsigned long frame, int readonly)
{
    grant_ref_t ref;

    ref = get_free_entry();
    gnttab_table[ref].frame = frame;
    gnttab_table[ref].domid = domid;
    wmb();
    readonly *= GTF_readonly;
    gnttab_table[ref].flags = GTF_permit_access | readonly;

    return ref;
}

grant_ref_t gnttab_grant_transfer(domid_t domid, unsigned long pfn)
{
    grant_ref_t ref;

    ref = get_free_entry();
    gnttab_table[ref].frame = pfn;
    gnttab_table[ref].domid = domid;
    wmb();
    gnttab_table[ref].flags = GTF_accept_transfer;

    return ref;
}

int gnttab_end_access(grant_ref_t ref)
{
    uint16_t flags, nflags;

    BUG_ON(ref >= NR_GRANT_ENTRIES || ref < NR_RESERVED_ENTRIES);

    nflags = gnttab_table[ref].flags;
    do {
        if ((flags = nflags) & (GTF_reading|GTF_writing)) {
            printk("WARNING: g.e. still in use! (%x)\n", flags);
            return 0;
        }
    } while ((nflags = synch_cmpxchg(&gnttab_table[ref].flags, flags, 0)) !=
            flags);

    put_free_entry(ref);
    return 1;
}

unsigned long gnttab_end_transfer(grant_ref_t ref)
{
    unsigned long frame;
    uint16_t flags;

    BUG_ON(ref >= NR_GRANT_ENTRIES || ref < NR_RESERVED_ENTRIES);

    while (!((flags = gnttab_table[ref].flags) & GTF_transfer_committed)) {
        if (synch_cmpxchg(&gnttab_table[ref].flags, flags, 0) == flags) {
            printk("Release unused transfer grant.\n");
            put_free_entry(ref);
            return 0;
        }
    }

    /* If a transfer is in progress then wait until it is completed. */
    while (!(flags & GTF_transfer_completed)) {
        flags = gnttab_table[ref].flags;
    }

    /* Read the frame number /after/ reading completion status. */
    rmb();
    frame = gnttab_table[ref].frame;

    put_free_entry(ref);

    return frame;
}

grant_ref_t gnttab_alloc_and_grant(void **map)
{
    unsigned long mfn;
    grant_ref_t gref;

    *map = (void *)memalign(PAGE_SIZE, PAGE_SIZE);
    mfn = virt_to_mfn(*map);
    gref = gnttab_grant_access(0, mfn, 0);
    return gref;
}

static const char * const gnttabop_error_msgs[] = GNTTABOP_error_msgs;

const char *gnttabop_error(int16_t status)
{
    status = -status;
    if (status < 0 || status >= ARRAY_SIZE(gnttabop_error_msgs))
        return "bad status";
    else
        return gnttabop_error_msgs[status];
}

void init_gnttab(void)
{
    struct xen_add_to_physmap xatp;
    struct gnttab_setup_table setup;
    xen_pfn_t frames[NR_GRANT_FRAMES];
    int i, rc;

    debug("%s\n", __func__);

    for (i = NR_RESERVED_ENTRIES; i < NR_GRANT_ENTRIES; i++)
        put_free_entry(i);

    gnttab_table = memalign(PAGE_SIZE, NR_GRANT_FRAMES * PAGE_SIZE);
    if (!gnttab_table) {
        printk("Cannot allocate grant table!\n");
        BUG();
    }

    for (i = 0; i < NR_GRANT_FRAMES; i++)
    {
        xatp.domid = DOMID_SELF;
        xatp.size = 0;
        xatp.space = XENMAPSPACE_grant_table;
        xatp.idx = i;
        xatp.gpfn = ((unsigned long)gnttab_table >> PAGE_SHIFT) + i;
        rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
        if (rc)
            printk("XENMEM_add_to_physmap failed; status = %d\n", rc);
        BUG_ON(rc != 0);
    }

    setup.dom = DOMID_SELF;
    setup.nr_frames = NR_GRANT_FRAMES;
    set_xen_guest_handle(setup.frame_list, frames);
    rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1);
    if (rc || setup.status)
    {
        printk("GNTTABOP_setup_table failed; status = %s\n",
               gnttabop_error(setup.status));
        BUG();
    }
}

void fini_gnttab(void)
{
    struct gnttab_setup_table setup;

    debug("%s\n", __func__);

    setup.dom = DOMID_SELF;
    setup.nr_frames = 0;

    HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1);
    if (setup.status) {
        printk("GNTTABOP_setup_table failed; status = %s\n",
               gnttabop_error(setup.status));
        BUG();
    }
    free(gnttab_table);
}

