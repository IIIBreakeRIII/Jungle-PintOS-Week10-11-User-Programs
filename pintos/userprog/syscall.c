#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/lib/kernel/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/*
	사용자 프로세스가 커널 기능에 접근하고자 할 때마다 시스템 콜을 호출합니다. 
	이것은 스켈레톤(기본 뼈대) 시스템 콜 핸들러입니다. 
	현재는 단순히 메시지를 출력하고 사용자 프로세스를 종료시키는 역할만 합니다. 
	이 프로젝트의 파트 2에서 여러분은 시스템 콜에 필요한 모든 다른 작업을 수행하는 코드를 추가하게 될 것입니다.
*/ 

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax) {
        case SYS_HALT:
            break;
        case SYS_EXIT:
			int status = f->R.rdi;
			thread_current()->exit_status = status;
			printf("%s: exit(%d)\n", thread_current()->name, status);
			thread_exit();
            break;
        case SYS_WRITE:  
            // 이 안에 `write` 시스템 콜의 상세 기능을 구현합니다.
            // 1. f->R.rdi, f->R.rsi, f->R.rdx에서 인자(fd, buffer, size)를 가져옵니다.
			int fd = f->R.rdi;
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			
            // 2. buffer 포인터가 유효한지 검사합니다.			
			// 3. fd가 1(콘솔 출력)인지, 일반 파일인지 구분합니다.
			if (fd == 1) {
				putbuf(buffer, size);
			} else {

			}
            // 4. 각 상황에 맞게 데이터를 씁니다.
            // 5. 쓴 바이트 수를 f->R.rax에 저장해서 반환합니다.
			f->R.rax;
            break;
        default:
            break;
    }

	// thread_exit ();
}
