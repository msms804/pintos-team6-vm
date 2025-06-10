/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "vm/uninit.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		case VM_ANON:
			return VM_TYPE(page->anon.type);
		case VM_FILE:
			return VM_TYPE(page->file.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* [Project 3] VM */
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
#define STACK_LIMIT (1 << 20)

/* Create the pending page object with initializer. If you want to create a
	* page, do not create it directly and make it through this function or
	* `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
										vm_initializer *init, void *aux)
{

	ASSERT (VM_TYPE(type) != VM_UNINIT);
	struct page *p = NULL;
	struct supplemental_page_table *spt = &thread_current ()->spt;
	
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		p = malloc(sizeof(struct page));
		if(p == NULL){
			return false;
		}

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			uninit_new(p, upage, init, type, aux, anon_initializer);
			break;
		case VM_FILE:
			uninit_new(p, upage, init, type, aux, file_backed_initializer);
			break;
		default:
			uninit_new(p, upage, init, type, aux, NULL);
			break;
		}

		p->writable = writable;

		if(!spt_insert_page(spt, p)){
			goto err;
		}
	}
	
	return true;
err:
	free(p);
	return false;
}

struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	if(va == NULL) return NULL;
	struct page *page = malloc(sizeof(struct page));
	page->va = pg_round_down(va);
	struct hash_elem *el = hash_find(&spt->hash_table, &page->h_elem);
	free(page);
	if(el != NULL){
		page = hash_entry(el, struct page, h_elem);
		return page;
	}
	return NULL;
}

bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;

	struct hash_elem *elem = hash_insert(&spt->hash_table, &page->h_elem);

	return elem == NULL ? true : false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = malloc(sizeof(struct frame));
	if(frame == NULL){
		free(frame);
		return NULL;
	}
	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);
	if(frame->kva == NULL){
		free(frame);
		return NULL;
	}

	frame->page = NULL;
	ASSERT(frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr UNUSED) {
	/* Increases the stack size by allocating one or more anonymous pages
	 so that addr is no longer a faulted address. Make sure you round down 
	 the addr to PGSIZE when handling the allocation.*/
	void *upage = pg_round_down(addr);
	int cnt = 0;
	while(!spt_find_page(&thread_current()->spt, upage + cnt * PGSIZE)){
		cnt++;
	}
	for(int i = 0; i < cnt; i++){
		if (!vm_alloc_page_with_initializer(VM_ANON | VM_MARKER_0, upage + i * PGSIZE, true, NULL, NULL))
		{
			return false;
		}
		if(!vm_claim_page(upage + i * PGSIZE)){
			return false;
		}
	}
	return true;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	if (addr == NULL || is_kernel_vaddr(addr) || !not_present){
		return false;
	}

	void *rsp = f->rsp;
	if(!user){	// 커널 모드에서 발생한 예외일 경우 커널 스택 포인터가 들어가 있을 수 있다.
		rsp = thread_current()->rsp;
	}
	if(USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 <= addr && addr <= USER_STACK){
		vm_stack_growth(addr);
	}

	page = spt_find_page(spt, addr);
	if(page == NULL){
		return false;
	}
	
	if(write && !page->writable){
		return false;
	}
	
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	struct thread *curr = thread_current();
	page = spt_find_page(&curr->spt, va);
	if (page == NULL)
	{
		return false;
	}

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();
	if(frame == NULL) return false;
	/* Set links */
	frame->page = page;
	page->frame = frame;
	if(!pml4_set_page(curr->pml4, page->va, frame->kva, page->writable)){
		return false;
	}
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
// 보조 페이지 테이블 초기화. initd 또는 do_fork가 호출.
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, h_elem);
	const struct page *b = hash_entry(b_, struct page, h_elem);

	return a->va < b->va;
}

/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, h_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {

	struct hash_iterator i;
	hash_first(&i, &src->hash_table);
	while (hash_next(&i))
	{
		struct page *src_page = hash_entry(hash_cur(&i), struct page, h_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;

		/* 1) type이 uninit이라면 */
		if (type == VM_UNINIT)
		{
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(src_page->uninit.type, upage, writable, init, aux);
			continue;
		}

		/* 2) type이 uninit이 아니면 */
		if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
			return false;

		if (!vm_claim_page(src_page->va))
		{
			return false;
		}

		struct page *dst_page = spt_find_page(dst, src_page->va);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	
	return true;
}

static void page_destroy(struct hash_elem *e, void *aux UNUSED)
{
	struct page *p = hash_entry(e, struct page, h_elem);
	destroy(p);
	free(p);
}
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->hash_table, page_destroy);
}