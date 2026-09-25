.section .text32, "ax"
.global ram32_start
.code32

ram32_start:
	# stash kernel length
	movl %ecx, %ebx

	# DEBUG signal to the hypervisor that this is the firmware entry point
	movl $0xC0010130, %ecx
	xorl %eax, %eax
	xorl %edx, %edx
	movl $0x14, %eax
	wrmsr
	rep vmmcall

validate_L2:
	movl $L2_TABLES + 4, %edi
	movl $0xfff, %eax
	notl %eax
	andl %eax, %edi

pvalidate_L2:
	# validate the pages we need for initial page tables
	movl %edi, %eax
	# page size, 0 = 4k, 1 = 2mb
	movl $0, %ecx
	# valid bit
	movl $1, %edx

	pvalidate
	
	# get carry flag
	setc %dl

	# check for success (0)
	cmp  $0, %eax
	jne  error
	
	# check if rmp was actually updated (CF = 0)
	cmp  $0, %dl
	jne   error

pvalidate_L2_done:
	xor	 %eax, %eax
	xor  %edi, %edi
validate_L3:
	movl $L3_TABLE + 4, %edi
	movl $0xfff, %eax
	notl %eax
	andl %eax, %edi
pvalidate_L3:
	# validate the pages we need for initial page tables
	movl %edi, %eax
	# page size, 0 = 4k, 1 = 2mb
	movl $0, %ecx
	# valid bit
	movl $1, %edx

	pvalidate
	
	# get carry flag
	setc %dl

	# check for success (0)
	cmp  $0, %eax
	jne  error
	
	# check if rmp was actually updated (CF = 0)
	cmp  $0, %dl
	jne   error
pvalidate_L3_done:
	xor	 %eax, %eax
	xor  %edi, %edi
validate_L4:
	movl $L4_TABLE + 4, %edi
	movl $0xfff, %eax
	notl %eax
	andl %eax, %edi
pvalidate_L4:
	# validate the pages we need for initial page tables
	movl %edi, %eax
	# page size, 0 = 4k, 1 = 2mb
	movl $0, %ecx
	# valid bit
	movl $1, %edx

	pvalidate
	
	# get carry flag
	setc %dl

	# check for success (0)
	cmp  $0, %eax
	jne  error
	
	# check if rmp was actually updated (CF = 0)
	cmp  $0, %dl
	jne   error
pvalidate_L4_done:
	xor	 %eax, %eax
	xor  %edi, %edi

validate_stack:
	# start at stack_start and move backwards
	movl $stack_start, %edi
	subl $0x1000, %edi

	# stack is 128k
	# need to loop 32 times to validate entire stack
	movl $32, %esi
pvalidate_stack:
	movl %edi, %eax
	# page size, 0 = 4k, 1 = 2mb
	movl $0, %ecx
	# valid bit
	movl $1, %edx

	pvalidate
	# get carry flag
	setc %dl

	# check for success (0)
	cmp  $0, %eax
	jne  error
	
	# check if rmp was actually updated (CF = 0)
	cmp  $0, %dl
	jne  error

	subl $0x1000, %edi
	
	subl $1, %esi
	cmp  $0, %esi
	jne  pvalidate_stack

setup_page_tables:

	movl $51, %eax
	subl $32, %eax
	bts  %eax, %edx

	# First L2 entry identity maps [0, 2 MiB)
	movl $0b10000011, (L2_TABLES) # huge (bit 7), writable (bit 1), present (bit 0)
	movl %edx, (L2_TABLES+4)
	
	# First L3 entry points to L2 table
	movl $L2_TABLES, %eax
	orb  $0b00000011, %al # writable (bit 1), present (bit 0)
	movl %eax, (L3_TABLE)
	movl %edx, (L3_TABLE+4)
	
	# First L4 entry points to L3 table
	movl $L3_TABLE, %eax
	orb  $0b00000011, %al # writable (bit 1), present (bit 0)
	movl %eax, (L4_TABLE)
	movl %edx, (L4_TABLE+4)

enable_paging:
	# Load page table root into CR3
	movl $L4_TABLE, %eax
	movl %eax, %cr3

	# Set CR4.PAE (Physical Address Extension)
	movl %cr4, %eax
	orb  $0b00100000, %al # Set bit 5
	movl %eax, %cr4
	
	# Set EFER.LME (Long Mode Enable)
	movl $0xC0000080, %ecx
	rdmsr
	orb  $0b00000001, %ah # Set bit 8
	wrmsr
	
	# Set CRO.PG (Paging)
	movl %cr0, %eax
	orl  $(1 << 31), %eax
	movl %eax, %cr0

jump_to_64bit:
	# We are now in 32-bit compatibility mode. To enter 64-bit mode, we need to
	# load a 64-bit code segment into our GDT.
	lgdtl GDT64_PTR
	
	# Initialize the stack pointer (Rust code always uses the stack)
	# Set segment registers to a 64-bit segment.
	movw $0x10, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %gs
	movw %ax, %fs
	movw %ax, %ss

	movl $stack_start, %esp

	movl $stack_start, %esi

	movl %ebx, %edi
	# Set CS to a 64-bit segment and jump to 64-bit Rust code.
	ljmpl $0x08, $rust64_start

error:
	hlt
	jmp error
