#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/lib/kernel/stdio.h"
#include "include/threads/init.h"
#include "include/filesys/filesys.h"

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
			power_off();
            break;
        case SYS_EXIT:
			int status = f->R.rdi;
			sys_exit(status);
            break;
        case SYS_WRITE:  
			int fd = f->R.rdi;
			void* buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			sys_write(fd, buffer, size);
            break;
		case SYS_CREATE:
			/*
				1. 인자가져오기
				intr_frame에서 첫 번째 인자인 const char *file (파일 이름이 담긴 주소)을 가져옵니다. 이 값은 %rdi 레지스터에 있습니다.
				2. 포인터 유효성 검사 (매우 중요)
				사용자 프로그램이 전달한 file 포인터가 유효한 주소인지 반드시 검사해야 합니다.
				이전에 만드신 is_valid_user_buffer와 같은 헬퍼 함수를 사용해, 주소가 NULL은 아닌지, 
				커널 영역을 침범하지는 않는지, 실제로 할당된 메모리가 맞는지 확인해야 합니다.
				유효하지 않다면, 즉시 프로세스를 종료시키거나(exit(-1)) 에러를 반환해야 합니다.
				3. 동기화: 락(Lock) 획득
				파일 시스템에 접근하는 것은 여러 프로세스가 동시에 할 수 없는 **임계 구역(Critical Section)**입니다.
				실제 파일을 열기 전에, 파일 시스템 접근을 보호하는 전역 락(lock)을 반드시 획득해야 합니다.
				4. 실제 파일 열기
				filesys/filesys.h에 선언된 filesys_open(file) 함수를 호출하여 실제 파일 열기를 시도합니다.
				이 함수는 성공 시 struct file 포인터를, 실패 시 NULL을 반환합니다.
				5. 파일 디스크립터 할당
				filesys_open이 성공하여 struct file 포인터를 받았다면, 이제 이 파일 객체를 현재 프로세스의 파일 디스크립터 테이블에 등록해야 합니다.
				struct thread 안에 struct file **fd_table;과 같은 배열을 만들어 관리합니다.
				테이블의 비어있는 가장 낮은 번호(2번부터 시작)를 찾아, 그 위치에 방금 받은 struct file 포인터를 저장합니다.
				이때 찾은 배열의 인덱스 번호가 바로 사용자 프로그램에게 돌려줄 **파일 디스크립터(fd)**가 됩니다.
				6. 동기화: 락(Lock) 해제
				파일 시스템 작업이 모두 끝났으므로, 3번에서 획득했던 락을 반드시 해제해야 합니다.
				7. 결과 반환
				성공 시: 5번에서 할당한 파일 디스크립터(fd) 번호를 intr_frame의 rax 레지스터에 저장합니다.
				실패 시 (filesys_open이 NULL을 반환했거나, 파일 디스크립터 테이블이 꽉 찼을 경우): **-1**을 rax 레지스터에 저장합니다. 
			*/
			char* file_name = f->R.rdi;
			is_valid_user_buffer(file_name, sizeof(file_name));
			struct thread* current_thread = thread_current();
			// lock_acquire(current_thread->acquired_locks);
			struct file* file = filesys_open(file_name);
			
			// lock_release(current_thread->acquired_locks);
			// f->R.rax = ;
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
