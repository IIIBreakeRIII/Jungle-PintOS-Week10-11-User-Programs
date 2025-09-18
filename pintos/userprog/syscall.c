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

#define EXIT_STATUS -1
#define MAX_BUFFER_SIZE 128

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool is_valid_user_buffer(void *buffer, unsigned size);
bool is_valid_user_string(char* user_string);
void sys_exit(int status);
bool sys_create(struct intr_frame *f UNUSED);
unsigned sys_write(struct intr_frame *f UNUSED);
void sys_close(struct intr_frame* f UNUSED);

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
			f->R.rax = sys_write(f);
            break;
		case SYS_CREATE:
			f->R.rax = sys_create(f);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f);
			break;
		case SYS_CLOSE:
			sys_close(f);
			break;
        default:
            break;
    }
}

void sys_close(struct intr_frame* f UNUSED) {
	int fd = f->R.rdi;
	struct thread* current_thread = thread_current();

	#ifdef USERPROG
		if (fd < 0 || fd >= FD_MAX || current_thread->fd_table[fd] == NULL) {
			sys_exit(EXIT_STATUS);
		}
		current_thread->fd_table[fd] = NULL;
		file_close(current_thread->fd_table[fd]);
	#endif
}

int sys_open(struct intr_frame* f UNUSED) {
	// 1. 인자가져오기
	char* file_name = f->R.rdi;
	struct thread* cur_thread = thread_current();

	// 2. 포인터 유효성 검사
	if (!is_valid_user_string(file_name)) {
		sys_exit(EXIT_STATUS);
	}

	// 3. 파일 열기 (동기화 포함)
	lock_acquire(&filesys_lock);
	struct file* file_obj = filesys_open(file_name);

	// 4. 파일 디스크립터 할당
	if (file_obj == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int fd = -1;
	#ifdef USERPROG
		for (int i = 3; i < FD_MAX; i++) {
			if (cur_thread->fd_table[i] == NULL) {
				cur_thread->fd_table[i] = file_obj;
				fd = i;
				break;
			}
		}
	#endif

	lock_release(&filesys_lock);

	if (fd == -1) {
        file_close(file_obj); // 열었던 파일도 다시 닫아줘야 함
    }
	// 5. 결과 반환
	return fd;
}

bool sys_create(struct intr_frame *f UNUSED) {
	char* file_name = f->R.rdi;
	unsigned file_size = f->R.rsi;

	// 1. 포인터 유효성 검사
	if (!is_valid_user_buffer(file_name, file_size)) {
		sys_exit(EXIT_STATUS);
	}

	// 2. 동기화 락 획득 - 다른 스레드 및 프로세스가 접근 불가능한 임계구역 설정
	lock_acquire(&filesys_lock);
	// 3. 실제 파일 만들기
	bool sucess = filesys_create(file_name, file_size);
	// 4. 락 동기화 해제
	lock_release(&filesys_lock);
	return sucess;
}


unsigned sys_write(struct intr_frame *f UNUSED) {
	int fd = f->R.rdi;
	void* buffer = f->R.rsi;
	unsigned size = f->R.rdx;

	if (!is_valid_user_buffer(buffer, size)) {
		sys_exit(EXIT_STATUS);
	}

	if (fd == 1) {
		putbuf(buffer, size);
		
	}
	return size;
}

void sys_exit(int status) {
	struct thread* cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}

bool is_valid_user_string(char* user_string) {
	// 1. 시작 주소 기본 검사: 먼저 file 포인터 자체가 NULL이거나 사용자 영역을 벗어나는지 확인합니다.
	if (user_string == NULL || !is_user_vaddr(user_string)) {
		return false;
	}

	// 2. 커널 버퍼 준비: palloc_get_page나 char kernel_buffer[128] 등으로 커널 메모리에 임시 버퍼를 하나 만듭니다.
	char kernal_buffer[MAX_BUFFER_SIZE];

	// 3. 한 바이트씩 안전하게 복사:
	for (int i = 0; i < MAX_BUFFER_SIZE ; i++) {
		char* current_char_addr = user_string + i;
		if (!is_user_vaddr(current_char_addr) || pml4_get_page(thread_current()->pml4, current_char_addr) == NULL) {
			return false;
		}

		if (current_char_addr == '\0') {
            return true;
        }
		kernal_buffer[i] = user_string[i];
		
		if (i > 4096) { // PGSIZE
            return false;
        }
	}


	return true;
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
