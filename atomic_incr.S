
.global atomic_incr

/* This method increments the given address with the second value passed in */
atomic_incr:
    push %rbp
	mov %rsp,%rbp
	mov %rdi,-0x8(%rbp)
	mov %esi,-0xc(%rbp) ///REMOVE
	mov -0x8(%rbp),%rax
	mov -0xc(%rbp),%rdi //REMOVE
	////////////
	// mov $1, %rdi UNCOMMENT
	lock xadd %rdi, (%rax)
	//
	pop %rbp
	retq



	/*
	movl 4(%esp),%ecx; // Caller - saved : now holds first arg, a pointer
	//movl 8(%esp),%eax; // Caller - saved : holds second arg, a value to add
    movl $1, %eax
	lock xadd %eax, (%ecx) // Add the two values and store back into pointer
    ret // Return the value pre incrementation, to calling thread process
	*/
