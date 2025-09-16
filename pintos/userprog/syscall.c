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
bool is_valid_user_buffer(void *buffer, unsigned size);
void sys_exit(int status);

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
			sys_exit(status);
            break;
        case SYS_WRITE:  
            // 이 안에 `write` 시스템 콜의 상세 기능을 구현합니다.
            // 1. f->R.rdi, f->R.rsi, f->R.rdx에서 인자(fd, buffer, size)를 가져옵니다.
			int fd = f->R.rdi;
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			sys_write(fd, buffer, size);
			
            break;
        default:
            break;
    }

	// thread_exit ();
}

void sys_write(int fd, void* buffer, unsigned size) {
	if (is_valid_user_buffer(buffer, size)) {
		if (fd == 1) {
			putbuf(buffer, size);
			// f->R.rax = size;
		} else {
			thread_exit();
		}
	}
}

void sys_exit(int status) {
	struct thread* cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}

// buffer부터 size 바이트까지의 모든 주소가 유효한지 확인하는 함수
bool is_valid_user_buffer(void *buffer, unsigned size) {
	bool flag = true;

    // 1. buffer 시작 주소가 유효한지 확인
	// 2. buffer + size - 1 끝 주소가 유효한지 확인
	if (buffer == NULL || !is_user_vaddr(buffer)|| !is_user_vaddr(buffer + size - 1)) {
		return false;
	}

    // 3. 그 사이의 모든 페이지들이 매핑되어 있는지 반복문으로 확인
    //    (pml4_get_page를 사용)
	void *current_page = pg_round_down(buffer); // 시작 페이지 계산
    void *end_page = pg_round_down(buffer + size - 1); // 끝 페이지 계산

    while (current_page <= end_page) {
        // 3. 각 페이지가 실제 메모리에 매핑되었는지 확인
        if (pml4_get_page(thread_current()->pml4, current_page) == NULL) {
            return false; // 매핑되지 않았으면 실패
        }
        current_page += PGSIZE; // 다음 페이지로 이동
    }
    
    // 모든 검사를 통과하면 true, 하나라도 실패하면 false 반환
	return true;
}
