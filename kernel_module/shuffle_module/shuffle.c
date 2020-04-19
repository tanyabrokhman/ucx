//#include <asm/uaccess.h> /* copy_from_user */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/hugetlb.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/pfn.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/cma.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/syscalls.h>
#include <asm/tlbflush.h>
#include <linux/swapops.h>
#include <linux/linkage.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

#include "shuffle.h"
#define flush_tlb_range_orig(vma, start, end)				\
	flush_tlb_mm_range_orig((vma)->vm_mm, start, end,		\
			   ((vma)->vm_flags & VM_HUGETLB)		\
				? huge_page_shift(hstate_vma(vma))	\
				: PAGE_SHIFT, false)


void (*flush_tlb_batched_pending)(struct mm_struct *mm);
void (*flush_tlb_mm_range_orig)(struct mm_struct *mm, unsigned long start,
		unsigned long end, unsigned int stride_shit, bool freed_tables);

static const char *filename = "shuffle_pages";
static struct proc_dir_entry* shuffle_proc_file;

static pte_t move_soft_dirty_pte(pte_t pte)
{
	/*
	 * Set soft dirty bit so we can notice
	 * in userspace the ptes were moved.
	 */
#ifdef CONFIG_MEM_SOFT_DIRTY
	if (pte_present(pte))
		pte = pte_mksoft_dirty(pte);
	else if (is_swap_pte(pte))
		pte = pte_swp_mksoft_dirty(pte);
#endif
	return pte;
}

static struct task_struct *find_get_task_vpid_safe(unsigned long to_pid) {
	struct task_struct *to_task = NULL;

	rcu_read_lock();
	to_task = pid_task(find_pid_ns(to_pid, task_active_pid_ns(current)), PIDTYPE_PID);

	if (!to_task) {
		rcu_read_unlock();
		return NULL;
	}

	get_task_struct(to_task);
	rcu_read_unlock();

	return to_task;
}

static pmd_t *get_pmd(struct mm_struct *mm, unsigned long addr) {
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static inline void shuffle_page_rmap_pte(pte_t from_pte_v,
	       	pte_t to_pte_v) {
	struct address_space *from_add_space;
	unsigned long from_pfn, to_pfn;
	struct page *from_page, *to_page;
	pgoff_t from_index;

	from_pfn = pte_pfn(from_pte_v);
	to_pfn = pte_pfn(to_pte_v);
	from_page = pfn_to_page(from_pfn);
	to_page = pfn_to_page(to_pfn);

	lock_page(from_page);
	lock_page(to_page);
	from_index = from_page->index;
	from_add_space = from_page->mapping;

	from_page->index = to_page->index;
	from_page->mapping = to_page->mapping;
	to_page->index = from_index;
	to_page->mapping = from_add_space;

	unlock_page(from_page);
	unlock_page(to_page);
}

static inline void shuffle_page_rmap_pmd(struct mm_struct *from_mm,
		pmd_t *from_pmd, unsigned long from_addr,
	       	struct mm_struct *to_mm, pmd_t *to_pmd,
		unsigned long to_addr) {
	pte_t *from_pte, *to_pte;
	spinlock_t *from_ptl, *to_ptl;
	unsigned long from_end;

	from_end = from_addr + PMD_SIZE;
	from_pte = pte_offset_map_lock(from_mm, from_pmd, from_addr,
		       	&from_ptl);
	to_pte = pte_offset_map_lock(to_mm, to_pmd, to_addr, &to_ptl);

	for (; from_addr < from_end; from_pte++, from_addr += PAGE_SIZE,
				   to_pte++)
		shuffle_page_rmap_pte(*from_pte, *to_pte);

	pte_unmap_unlock(from_pte - 1, from_ptl);
	pte_unmap_unlock(to_pte - 1, to_ptl);
}

static void shuffle_pmds(struct vm_area_struct *from_vma, pmd_t *from_pmd,
		unsigned long from_addr, unsigned long from_end,
		struct vm_area_struct *to_vma, pmd_t *to_pmd,
	       	unsigned long to_addr, unsigned long to_end,
	       	bool need_rmap_locks, bool *need_flush) {
	struct mm_struct *from_mm = from_vma->vm_mm;
	struct mm_struct *to_mm = to_vma->vm_mm;
	pmd_t from_pmd_v, to_pmd_v;
	spinlock_t *from_ptl, *to_ptl;
	bool force_flush_from = false, force_flush_to = false;
	unsigned long len = from_end - from_addr;

	/*
	 * When need_rmap_locks is true, we take the i_mmap_rwsem and anon_vma
	 * locks to ensure that rmap will always observe either the old or the
	 * new ptes. This is the easiest way to avoid races with
	 * truncate_pagecache(), page migration, etc...
	 *
	 * When need_rmap_locks is false, we use other ways to avoid
	 * such races:
	 *
	 * - During exec() shift_arg_pages(), we use a specially tagged vma
	 *   which rmap call sites look for using is_vma_temporary_stack().
	 *
	 * - During mremap(), new_vma is often known to be placed after vma
	 *   in rmap traversal order. This ensures rmap will always observe
	 *   either the old pte, or the new pte, or both (the page table locks
	 *   serialize access to individual ptes, but only rmap traversal
	 *   order guarantees that we won't miss both the old and new ptes).
	 */
	if (need_rmap_locks) {
		anon_vma_lock_write(from_vma->anon_vma);
		anon_vma_lock_write(to_vma->anon_vma);
	}

	/*
	 * We don't have to worry about the ordering of src and dst
	 * pte locks because exclusive mmap_sem prevents deadlock.
	 */

	from_ptl = pmd_lock(from_mm, from_pmd);
	to_ptl = pmd_lock(to_mm, to_pmd);

	flush_tlb_batched_pending(from_mm);
	flush_tlb_batched_pending(to_mm);

	if (pmd_none(*from_pmd) || pmd_none(*to_pmd)){
		/* TODO: take care in case of error */
		BUG();
	}

	shuffle_page_rmap_pmd(from_mm, from_pmd, from_addr, to_mm,
			to_pmd, to_addr);

	from_pmd_v = pmdp_huge_get_and_clear(from_mm, from_addr, from_pmd);
	to_pmd_v = pmdp_huge_get_and_clear(to_mm, to_addr, to_pmd);

	/*
	 * If we are remapping a dirty PTE, make sure
	 * to flush TLB before we drop the PTL for the
	 * old PTE or we may race with page_mkclean().
	 *
	 * This check has to be done after we removed the
	 * old PTE from page tables or another thread may
	 * dirty it after the check and before the removal.
	 */
	/* TODO: if one of the pages is dirty we need to flush */
	/* if (pte_present(from_pte_v) && pte_dirty(from_pte_v))
		force_flush_from = true;
	   if (pte_present(to_pte_v) && pte_dirty(to_pte_v))
		force_flush_to = true;
	*/

	/* TODO: this for every PTE? */
	/*  from_pte_v = move_soft_dirty_pte(from_pte_v); */

	set_pmd_at(to_mm, to_addr, to_pmd, from_pmd_v);
//	set_pmd_at(to_mm, to_addr, to_pmd, pfn_pmd(pmd_pfn(from_pmd_v),
//				       	to_vma->vm_page_prot));

	/* TODO: this for every PTE? */
	/* to_pte_v = move_soft_dirty_pte(to_pte_v); */
	set_pmd_at(from_mm, from_addr, from_pmd, to_pmd_v);
//	set_pmd_at(from_mm, from_addr, from_pmd, pfn_pmd(pmd_pfn(to_pmd_v),
//			       	from_vma->vm_page_prot));

	if (force_flush_from)
		flush_tlb_range_orig(from_vma, from_end - len, from_end);
	else
		*need_flush = true;

	if (force_flush_to)
		flush_tlb_range_orig(to_vma, to_end - len, to_end);
	else
		*need_flush = true;

	spin_unlock(from_ptl);
	spin_unlock(to_ptl);

	if (need_rmap_locks) {
		anon_vma_unlock_write(from_vma->anon_vma);
		anon_vma_unlock_write(to_vma->anon_vma);
	}
}

static void shuffle_ptes(struct vm_area_struct *from_vma, pmd_t *from_pmd,
		unsigned long from_addr, unsigned long from_end,
		struct vm_area_struct *to_vma, pmd_t *to_pmd,
	       	unsigned long to_addr, unsigned long to_end,
	       	bool need_rmap_locks, bool *need_flush) {
	struct mm_struct *from_mm = from_vma->vm_mm;
	struct mm_struct *to_mm = to_vma->vm_mm;
	pte_t *from_pte, *to_pte, from_pte_v, to_pte_v;
	spinlock_t *from_ptl, *to_ptl;
	bool force_flush_from = false, force_flush_to = false;
	unsigned long len = from_end - from_addr;

	/*
	 * When need_rmap_locks is true, we take the i_mmap_rwsem and anon_vma
	 * locks to ensure that rmap will always observe either the old or the
	 * new ptes. This is the easiest way to avoid races with
	 * truncate_pagecache(), page migration, etc...
	 *
	 * When need_rmap_locks is false, we use other ways to avoid
	 * such races:
	 *
	 * - During exec() shift_arg_pages(), we use a specially tagged vma
	 *   which rmap call sites look for using is_vma_temporary_stack().
	 *
	 * - During mremap(), new_vma is often known to be placed after vma
	 *   in rmap traversal order. This ensures rmap will always observe
	 *   either the old pte, or the new pte, or both (the page table locks
	 *   serialize access to individual ptes, but only rmap traversal
	 *   order guarantees that we won't miss both the old and new ptes).
	 */
	if (need_rmap_locks) {
		anon_vma_lock_write(from_vma->anon_vma);
		anon_vma_lock_write(to_vma->anon_vma);
	}

	/*
	 * We don't have to worry about the ordering of src and dst
	 * pte locks because exclusive mmap_sem prevents deadlock.
	 */

	from_pte = pte_offset_map_lock(from_mm, from_pmd, from_addr, &from_ptl);
	to_pte = pte_offset_map_lock(to_mm, to_pmd, to_addr, &to_ptl);

	flush_tlb_batched_pending(from_mm);
	flush_tlb_batched_pending(to_mm);

	for (; from_addr < from_end; from_pte++, from_addr += PAGE_SIZE,
				   to_pte++, to_addr += PAGE_SIZE) {
		if (pte_none(*from_pte) || pte_none(*to_pte)){
			pr_err("PTE NONE %lx %lx !!\n", from_pte->pte,
					to_pte->pte);
			/* TODO: take care in case of error */
			BUG();
		}

		/* TODO: skip the clear? */

		from_pte_v = ptep_get_and_clear(from_mm, from_addr, from_pte);
		to_pte_v = ptep_get_and_clear(to_mm, to_addr, to_pte);


		shuffle_page_rmap_pte(from_pte_v, to_pte_v);

		/* update rmapping to new anon_vma */
		/*
		 * If we are remapping a dirty PTE, make sure
		 * to flush TLB before we drop the PTL for the
		 * old PTE or we may race with page_mkclean().
		 *
		 * This check has to be done after we removed the
		 * old PTE from page tables or another thread may
		 * dirty it after the check and before the removal.
		 */
		if (pte_present(from_pte_v) && pte_dirty(from_pte_v))
			force_flush_from = true;
		if (pte_present(to_pte_v) && pte_dirty(to_pte_v))
			force_flush_to = true;

		from_pte_v = move_pte(from_pte_v, to_vma->vm_page_prot,
			       	from_addr, to_addr);
		from_pte_v = move_soft_dirty_pte(from_pte_v);
		set_pte_at(to_mm, to_addr, to_pte,
			       	pfn_pte(pte_pfn(from_pte_v),
				       	to_vma->vm_page_prot));

		to_pte_v = move_pte(to_pte_v, from_vma->vm_page_prot,
			       	to_addr, from_addr);
		to_pte_v = move_soft_dirty_pte(to_pte_v);
		set_pte_at(from_mm, from_addr, from_pte,
			       	pfn_pte(pte_pfn(to_pte_v),
				       	from_vma->vm_page_prot));
	}

	arch_leave_lazy_mmu_mode();

	if (force_flush_from)
		flush_tlb_range_orig(from_vma, from_end - len, from_end);
	else
		*need_flush = true;

	if (force_flush_to)
		flush_tlb_range_orig(to_vma, to_end - len, to_end);
	else
		*need_flush = true;

	pte_unmap_unlock(from_pte - 1, from_ptl);
	pte_unmap_unlock(to_pte - 1, to_ptl);
	if (need_rmap_locks) {
		anon_vma_unlock_write(from_vma->anon_vma);
		anon_vma_unlock_write(to_vma->anon_vma);
	}
}

static unsigned long mshuffle_batch(struct mm_struct *from_mm,
		unsigned long from_addr, struct mm_struct *to_mm,
	       	unsigned long to_addr, unsigned long nr_pages)
{

	struct vm_area_struct *from_vma, *to_vma;
	unsigned long extent_from, extent_to, extent;
	unsigned long next_from, next_to, from_end, to_end, len;
	bool need_flush = false;
	from_vma = find_vma(from_mm, from_addr);
	to_vma = find_vma(to_mm, to_addr);
	extent_from = 0;
	extent_to = 0;
	extent = 0;

	len = PAGE_SIZE * nr_pages;
	from_end = from_addr + len;
	to_end = to_addr + len;

	for (; from_addr < from_end; from_addr += extent, to_addr += extent) {
		pmd_t *from_pmd, *to_pmd;

		/* if both are aligned and have at least PMD_SIZE remaining,
		 * shuffle the PMDs themselved */
		next_from = (from_addr + PMD_SIZE) & PMD_MASK;
		/* even if next overflowed, extent below will be ok */
		extent_from = next_from - from_addr;
		if (extent_from > from_end - from_addr)
			extent_from = from_end - from_addr;

		next_to = (to_addr + PMD_SIZE) & PMD_MASK;
		extent_to = next_to - to_addr;
		if (extent_to > next_to - to_addr)
			extent_to = next_to - to_addr;

		extent = min(extent_to, extent_from);

		from_pmd = get_pmd(from_mm, from_addr);
		to_pmd = get_pmd(to_mm, to_addr);

		if (!from_pmd || !to_pmd)
			BUG();

		if (pmd_trans_huge(*from_pmd) || pmd_trans_huge(*to_pmd)) {
			/* TODO: enable huge pages */
			BUG();
		}

		/* if both addresses are aligned and of size PMD, exchange
		 * PMDs */
		if (extent == PMD_SIZE) {
			shuffle_pmds(from_vma, from_pmd, from_addr,
				       	from_addr + extent, to_vma, to_pmd,
				       	to_addr, to_end, false, &need_flush);
			continue;
		}

		shuffle_ptes(from_vma, from_pmd, from_addr, from_addr + extent,
			       	to_vma, to_pmd, to_addr, to_end, false,
			       	&need_flush);
	}

	if (need_flush) {
		flush_tlb_range_orig(from_vma, from_end-len, from_addr);
		flush_tlb_range_orig(to_vma, to_end-len, to_addr);
	}

	return len + from_addr - from_end;	/* how much done */
}

static int shuffle_pages(unsigned long from_addr, pid_t to_pid,
	       	unsigned long to_addr, unsigned long nr_pages)
{
	struct task_struct *to_task = NULL;
	struct mm_struct *from_mm = current->mm;
	struct mm_struct *to_mm;
	unsigned long ret = -EINVAL;

	pr_err("%s() enter: from_addr = 0x%llx,  to_pid = %d, to_addr = 0x%llx,  nr_pages = %lu\n",
	       	from_addr, to_pid, to_addr,  nr_pages);
	/* do not allow offsets inside pages for now */
	if (offset_in_page(from_addr) || offset_in_page(to_addr))
		return ret;

	/*  get task of dest pid */
	to_task = find_get_task_vpid_safe(to_pid);
	if (!to_task) {
		pr_err("Shuffle: did not find valid vpid\n");
		return -ESRCH;
	}

	to_mm = get_task_mm(to_task);
	put_task_struct(to_task);

	if (!to_mm) {
		ret = -EINVAL;
		goto error_put;
	}

	down_read(&to_mm->mmap_sem);
	down_read(&from_mm->mmap_sem);

	ret = mshuffle_batch(from_mm, from_addr, to_mm, to_addr, nr_pages);

	up_read(&to_mm->mmap_sem);
	up_read(&from_mm->mmap_sem);

error_put:
	mmput(to_mm);
	return ret;
}

static int open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return 0;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	return 0;
}

static ssize_t ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	pr_err("%s() enter\n");
	switch (cmd)
	{
	case SHUFFLE_IOCTL_SHUFFLE:
		{
			struct shuffle_args s_args= {0};
			if (copy_from_user(&s_args, (struct shuffle_args *)arg,
						sizeof(struct shuffle_args)))
				return -EFAULT;
			s_args.res = shuffle_pages(s_args.from_addr,
					s_args.to_pid,
					s_args.to_addr,
					s_args.nr_pages);
			if (copy_to_user((struct shuffle_args *)arg, &s_args,
						sizeof(struct shuffle_args)))
				return -EFAULT;
			return 0;
		}
	}
	return 0;
}

static int release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations fops = {
	.open = open,
	.release = release,
	.read = read,
	.write = write,
	.unlocked_ioctl = ioctl,
};

static int shuffle_init(void)
{
	flush_tlb_batched_pending = (void *)kallsyms_lookup_name("flush_tlb_batched_pending");
	flush_tlb_mm_range_orig = (void *)kallsyms_lookup_name("flush_tlb_mm_range");
	shuffle_proc_file = proc_create(filename, 0, NULL, &fops);

	if (!shuffle_proc_file) {
		pr_err("shuffle: could not create procfs file");
		return -ENOMEM;
	}
	pr_err("%s() enter\n");
	return 0;
}

static void shuffle_exit(void)
{
	pr_err("%s() enter\n");
	remove_proc_entry(filename, NULL);
}

module_init(shuffle_init)
module_exit(shuffle_exit)
MODULE_LICENSE("GPL");
