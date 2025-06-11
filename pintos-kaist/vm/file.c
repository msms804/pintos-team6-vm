/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct file_page *file_page = &page->file;
	struct segment_aux *seg_aux = (struct segment_aux *)page->uninit.aux;
	file_page->file = seg_aux->file;
	file_page->read_bytes = seg_aux->page_read_bytes;
	file_page->zero_bytes = seg_aux->page_zero_bytes;
	file_page->ofs = seg_aux->offset;
	file_page->va = page->va;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if(pml4_is_dirty(thread_current()->pml4, page->va)){
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, false);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	struct file *open_file = file_reopen(file);
	int total_page_count = length / PGSIZE;
	if (length % PGSIZE != 0)
		total_page_count += 1;
	size_t read_bytes = file_length(open_file) < length ? file_length(open_file) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);
	ASSERT(offset % PGSIZE == 0);

	void *ret_addr = addr;
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct segment_aux *seg_aux = (struct segment_aux *)malloc(sizeof(struct segment_aux));
		seg_aux->file = open_file;
		seg_aux->page_read_bytes = page_read_bytes;
		seg_aux->page_zero_bytes = page_zero_bytes;
		seg_aux->offset = offset;
		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, seg_aux))
			return NULL;
		struct page *p = spt_find_page(&thread_current()->spt, ret_addr);
		p->mapped_cnt = total_page_count;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return ret_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// while(true){
	// 	struct page *p = spt_find_page(&thread_current()->spt, addr);
	// 	struct segment_aux *aux = (struct segment_aux*)p->uninit.aux;

	// 	if(pml4_is_dirty(thread_current()->pml4, p->va)){
	// 		file_write_at(aux->file, addr, aux->page_read_bytes, aux->offset);
	// 		pml4_set_dirty(thread_current()->pml4, p->va, 0);
	// 	}

	// 	pml4_clear_page(thread_current()->pml4, p->va);
	// 	addr += PGSIZE;
	// }
	struct page *p = spt_find_page(&thread_current()->spt, addr);
	for(int i = 0; i < p->mapped_cnt; i++){
		if(p != NULL){
			destroy(p);
		}
		addr += PGSIZE;
		p = spt_find_page(&thread_current()->spt, addr);
	}
}
