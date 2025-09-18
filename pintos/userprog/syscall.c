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
#include "include/threads/init.h"

// pml4_get_page를 위해 추가
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool is_valid_user_buffer(void *buffer, unsigned size);

// syscall
// void sys_exit(int status);
// void sys_write(int fd, void *buffer, unsigend size);

void check_address(void *addr);

/* 시스템 콜.
 * 
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러에 의해 처리되었습니다
 * (예: 리눅스의 int 0x80). 하지만 x86-64에서는 제조사가
 * 시스템 콜 요청을 위한 효율적인 경로인 `syscall` 명령어를 제공합니다.
 * 
 * `syscall` 명령어는 모델 특정 레지스터(MSR)의 값을 읽어 동작합니다.
 * 자세한 내용은 매뉴얼을 참조하세요. */

#define MSR_STAR 0xc0000081         /* 세그먼트 셀렉터 MSR */
#define MSR_LSTAR 0xc0000082        /* 롱 모드 SYSCALL 타겟 */
#define MSR_SYSCALL_MASK 0xc0000084 /* eflags를 위한 마스크 */

void syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* 인터럽트 서비스 루틴은 syscall_entry가 유저랜드 스택을
	 * 커널 모드 스택으로 바꿀 때까지 어떠한 인터럽트도 처리해서는 안 됩니다.
	 * 따라서 FLAG_FL을 마스킹합니다. */
	write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

static void die_with_status (int status) {
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();   // 반환 안 함
}

// 사용자가 제공한 주소가 유효한지 확인하는 함수
void check_address(void *addr) {
  // case1 : 주소가 NULL이 아닌지
  // case2 : 주소가 사용자 영역 주소인지(커널 영역을 침범하지 않는지)
  // case3 : 주소가 실제 물리 메모리와 매핑된 페이지인지
  if (addr == NULL || !is_user_vaddr(addr) || pml4_get_page(thread_current() -> pml4, addr) == NULL) {
    // 유효하지 않을 경우, 프로세스를 종료
    die_with_status(-1);
  }
}

/* 주 시스템 콜 인터페이스 */
void syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: 여기에 구현을 추가하세요.
	switch (f->R.rax) {
    case SYS_HALT:
      // pintos 종료
      power_off();
      break;
    
    case SYS_EXIT:
			int status = f->R.rdi;
			thread_current()->exit_status = status;
			printf("%s: exit(%d)\n", thread_current()->name, status);
			thread_exit();
      break;
    
    case SYS_WRITE:
      // 인자 가져오기
      int fd = f->R.rdi;
      const char *buffer = (const char *)f->R.rsi;
      unsigned size = f->R.rdx;

      // buffer 주소 유효성 검사 : Buffer의 시작과 끝 주소 모두 확인
      check_address((void *)buffer);
      check_address((void *)(buffer + size - 1));

      // fd에 따라 처리 분기
      // case1 : fd == 0
      if (fd == 0) {
        // 표준 입력에 쓰는 것은 불가능 : 에러 처리
        f -> R.rax = -1;
      } else if (fd == 1) {
        // 표준 출력 : 화면에 버퍼 내용을 size만큼 출력
        putbuf(buffer, size);
        f -> R.rax = size;
      } else {
        // fd == 2일 경우,
        // 파일 쓰기는 아직 구현하지 않았으므로 에러 처리
        f->R.rax = -1;
      }
      break;

    default:
      break;
  }

	// thread_exit ();
}


bool is_valid_user_buffer(void *buffer, unsigned size) {
	bool flag = true;

	if (buffer == NULL || !is_user_vaddr(buffer)|| !is_user_vaddr(buffer + size - 1)) {
		return false;
	}

	void *current_page = pg_round_down(buffer);
  void *end_page = pg_round_down(buffer + size - 1);

  while (current_page <= end_page) {
    if (pml4_get_page(thread_current()->pml4, current_page) == NULL) {
      return false;
    }
      current_page += PGSIZE;
  }
    
	return true;
}

// syscall
// write
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

// exit
void sys_exit(int status) {
	struct thread* cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}