#ifndef _ASM_ARM_XEN_SYSTEM_H
#define _ASM_ARM_XEN_SYSTEM_H

#include <compiler.h>
#include <asm/bitops.h>

/* If *ptr == old, then store new there (and return new).
 * Otherwise, return the old value.
 * Atomic. */
#define synch_cmpxchg(ptr, old, new) \
({ __typeof__(*ptr) stored = old; \
   __atomic_compare_exchange_n(ptr, &stored, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ? new : old; \
})

/* As test_and_clear_bit, but using __ATOMIC_SEQ_CST */
static inline int synch_test_and_clear_bit(int nr, volatile void *addr)
{
	uint8_t *byte = ((uint8_t *)addr) + (nr >> 3);
	uint8_t bit = 1 << (nr & 7);
	uint8_t orig;

	orig = __atomic_fetch_and(byte, ~bit, __ATOMIC_SEQ_CST);

	return (orig & bit) != 0;
}

/* As test_and_set_bit, but using __ATOMIC_SEQ_CST */
static inline int synch_test_and_set_bit(int nr, volatile void *base)
{
	uint8_t *byte = ((uint8_t *)base) + (nr >> 3);
	uint8_t bit = 1 << (nr & 7);
	uint8_t orig;

	orig = __atomic_fetch_or(byte, bit, __ATOMIC_SEQ_CST);

	return (orig & bit) != 0;
}

/* As set_bit, but using __ATOMIC_SEQ_CST */
static inline void synch_set_bit(int nr, volatile void *addr)
{
	synch_test_and_set_bit(nr, addr);
}

/* As clear_bit, but using __ATOMIC_SEQ_CST */
static inline void synch_clear_bit(int nr, volatile void *addr)
{
	synch_test_and_clear_bit(nr, addr);
}

/* As test_bit, but with a following memory barrier. */
//static inline int synch_test_bit(int nr, volatile void *addr)
static inline int synch_test_bit(int nr, const void *addr)
{
	int result;
	result = test_bit(nr, addr);
	barrier();
	return result;
}

#define xchg(ptr,v)	__atomic_exchange_n(ptr, v, __ATOMIC_SEQ_CST)
#define xchg(ptr,v)	__atomic_exchange_n(ptr, v, __ATOMIC_SEQ_CST)

#define mb()		dsb()
#define rmb()		dsb();
#define wmb()		dsb();
#define __iormb()	dmb()
#define __iowmb()	dmb()
#define xen_mb()	mb()
#define xen_rmb()	rmb()
#define xen_wmb()	wmb()

#define smp_processor_id()	0

#define mfn_to_pfn(_mfn)	((unsigned long)(_mfn))
#define pfn_to_mfn(_pfn)	((unsigned long)(_pfn))

#define to_phys(x)		(virt_to_phys(x))
#define to_virt(x)		((void *)((unsigned long)(phys_to_virt))

#define virt_to_pfn(_virt)	(to_phys(_virt) >> PAGE_SHIFT)
#define virt_to_mfn(_virt)	(pfn_to_mfn(virt_to_pfn(_virt)))
#define mfn_to_virt(_mfn)	(to_virt(mfn_to_pfn(_mfn) << PAGE_SHIFT))
#define pfn_to_virt(_pfn)	(to_virt((_pfn) << PAGE_SHIFT))

#endif
