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
#include "threads/palloc.h"
#include "userprog/process.h"
#include "string.h"
#include "devices/input.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
bool is_valid_user_buffer(void *buffer, unsigned size);

// address check
void check_address(void *addr);

// System syscall
void sys_halt_handler(void);
void sys_exit_handler(int arg1);
bool sys_create_handler(const char *file, unsigned initial_size);
int sys_read_handler(int fd, void *buffer, unsigned size);
int sys_write_handler(int fd, const char *buffer, unsigned size);
int sys_open_handler(const char*filename);
int sys_exec_handler(const char *cmd_line);

// 전역 파일시스템 락 실제 정의
struct lock filesys_lock;

// 파일 디스크립터 관련 상수
#define FDBASE 2    // 표준 입출력(0,1) 제외하고 시작
#define FDLIMIT 64  // 최대 파일 디스크립터 개수

#define MSR_STAR 0xc0000081         /* 세그먼트 셀렉터 MSR */
#define MSR_LSTAR 0xc0000082        /* 롱 모드 SYSCALL 타겟 */
#define MSR_SYSCALL_MASK 0xc0000084 /* eflags를 위한 마스크 */

void syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

  lock_init(&filesys_lock);
}

static void die_with_status(int status) {
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
      sys_halt_handler();
      break;
    
    case SYS_EXIT:
			int status = f->R.rdi;
      sys_exit_handler(status);
      break;

    case SYS_CREATE:
      f->R.rax = sys_create_handler((const char *)f->R.rdi, f->R.rsi);
      break;

    case SYS_READ:
      f->R.rax = sys_read_handler(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
		  break;
    
    case SYS_WRITE:
      f->R.rax = sys_write_handler(f->R.rdi, (const char *)f->R.rsi, f->R.rdx);
      break;

    case SYS_OPEN:
      f->R.rax = sys_open_handler((const char *)f->R.rdi);
      break;

    case SYS_EXEC:
      f->R.rax = sys_exec_handler((const char *)f->R.rdi);
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

// syscall_halt
void sys_halt_handler(void) {
  power_off();
}

// syscall_exit
void sys_exit_handler(int arg1) {
  thread_current()->exit_status = arg1;
  printf("%s: exit(%d)\n", thread_current()->name, arg1);
	thread_exit();
}

bool sys_create_handler(const char *file, unsigned initial_size) {
  lock_acquire(&filesys_lock);
  check_address(file);

  bool success = filesys_create(file, initial_size);
  
  lock_release(&filesys_lock);

  return success;
}

// int sys_read_handler(int fd, void* buffer, unsigned size){
// 	struct thread *curr = thread_current();
// 	int result;
// 	if (fd < FDBASE || fd >= FDLIMIT || curr->fd_table[fd] == NULL || buffer == NULL || is_kernel_vaddr(buffer) || !pml4_get_page(curr->pml4, buffer))
// 	{
// 		thread_current()->exit_status = -1;
// 		thread_exit();
// 	}
// 	struct file *f = curr->fd_table[fd];
// 	lock_acquire(&filesys_lock);
// 	result = file_read(f, buffer, size);
// 	lock_release(&filesys_lock);
// 	return result;
// }

int sys_read_handler(int fd, void *buffer, unsigned size){
  if (size == 0) return 0;
  if (!is_valid_user_buffer(buffer, size)) {
      die_with_status(-1);
  }

  if (fd == 0) {
      unsigned i;
      for (i = 0; i < size; i++) {
          ((char *)buffer)[i] = input_getc();
      }
      return (int) size;
  }

  // 파일 입력은 아직 미구현
  return -1;
}

int sys_exec_handler(const char *cmd_line) {
  struct thread *curr = thread_current();
  if (cmd_line == NULL || !is_user_vaddr(cmd_line) || pml4_get_page(curr->pml4, cmd_line) == NULL) {
    die_with_status(-1);
  }

  char *fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    return -1;
  }
  strlcpy(fn_copy, cmd_line, PGSIZE);
  return process_exec(fn_copy);
}

int sys_write_handler(int fd, const char *buffer, unsigned size) {
  // check_address((void *)buffer);
  // check_address((void *)(buffer + size - 1));
  //
  // // fd에 따라 처리 분기
  // // case1 : fd == 0
  // if (fd == 0) {
  //   // 표준 입력에 쓰는 것은 불가능 : 에러 처리
  //   f -> R.rax = -1;
  // } else if (fd == 1) {
  //   // 표준 출력 : 화면에 버퍼 내용을 size만큼 출력
  //   putbuf(buffer, size);
  //   f -> R.rax = size;
  // } else {
  //   // fd == 2일 경우,
  //   // 파일 쓰기는 아직 구현하지 않았으므로 에러 처리
  //   f->R.rax = -1;
  // }
  if (!is_valid_user_buffer((void *)buffer, size)) {
    die_with_status(-1);
  }

  if (fd == 1) {
    putbuf(buffer, size);
    return (int) size;
  }

  return 0;
}

int sys_open_handler(const char *filename){
	// return -1;
	struct thread *curr = thread_current();
	if (!(filename && is_user_vaddr(filename) && pml4_get_page(curr->pml4, filename))) {
		curr->exit_status = -1;
		thread_exit();
	}

	lock_acquire(&filesys_lock);
	struct file *file = filesys_open(filename);
	lock_release(&filesys_lock);
	
  if (!file) {
    return -1;
  }

	struct file **f_table = curr->fd_table;
	int i = FDBASE;
	
  for (; i < FDLIMIT; i++) {
		if (f_table[i] == NULL) {
			f_table[i] = file;
			return i;
		}
	}

	lock_acquire(&filesys_lock);
	file_close(file);
	lock_release(&filesys_lock);
	
  return -1;
}
