#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "include/lib/kernel/stdio.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"
#include "include/filesys/file.h"
#include "list.h"

#ifdef VM
#include "vm/vm.h"
#endif

#define MAX_BUFFER_SIZE 128

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
void user_stack_build(struct intr_frame* if_, int argc, char* argv_temp[]);

// struct fork_aux {
//     struct intr_frame parent_if;      /* 부모의 intr_frame(레지스터 컨텍스트)을 '값'으로 통째 복사해 담아둠 */
//     struct thread *parent;
//     struct semaphore done;            /* 부모-자식 동기화용 세마포어: 자식 준비 완료 알림 */
//     bool success;                     /* 자식이 복제에 성공했는지 부모에게 알려줄 플래그 */
//     struct wait_status *w;            /* 부모-자식 wait/exit 상태 공유 객체 포인터 */
// };

// ELF 바이너리를 로드하고 프로세스를 시작합니다.

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	#ifdef USERPROG
		current->fd_table = malloc(sizeof(struct file *) * FD_MAX);
		for (int i = 0; i < FD_MAX; i++) {
			current->fd_table[i] = NULL;
		}
	#endif
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	
	struct thread* current_thread = thread_current();
	struct thread* child_thread = get_thread_by_tid(tid);
	child_thread->parent = current_thread;

    if (child_thread == NULL) {
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }
	list_push_back(&current_thread->child_list, &child_thread->child_elem);
	
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	// process_init ();
	struct thread* parent = thread_current();
	parent->parent_if = if_;

	tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, parent);
	if (tid == TID_ERROR) {
    	return TID_ERROR; 
	}

	struct thread* child = get_thread_by_tid(tid);
	if (child == NULL) {
		return TID_ERROR;
	}

	list_push_back(&parent->child_list, &child->child_elem);
	sema_down(&child->fork_sema);

	if (child->exit_status == -1) { 
		list_remove(&child->child_elem);
    	return TID_ERROR;
	}

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	/* 1. TODO: 만약 부모의 페이지가 커널 페이지라면, 즉시 반환하세요. */
	if (is_kernel_vaddr(va)) {
		return true;
	}
	
	/* 2. Resolve VA from the parent's page map level 4. */
	/* 2. 부모의 페이지 맵 레벨 4에서 가상 주소(VA)를 해석합니다.*/ 
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL) {
		return false;
	}
	
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	/* 3. TODO: 자식을 위해 새로운 PAL_USER 페이지를 할당하고, 그 결과를
	 * TODO: NEWPAGE에 설정하세요. */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	/* 4. TODO: 부모의 페이지를 새 페이지로 복제하고,
	 * TODO: 부모 페이지의 쓰기 가능 여부를 확인하세요 (그 결과에 따라
	 * TODO: WRITABLE을 설정). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	/* 5. WRITABLE 권한으로, 가상 주소 VA에 있는 자식의 페이지 테이블에 새 페이지를 추가합니다. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		/* 6. TODO: 만약 페이지 삽입에 실패하면, 에러 처리를 하세요. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */

 
// 현재 프로세스를 복제하여 THREAD_NAME이라는 이름의 새 프로세스를 생성합니다.

/*
- **부모 프로세스:** 새로 생성된 자식 프로세스의 `pid` (프로세스 ID)를 반환합니다. 
자식 프로세스 복제에 실패하면 `TID_ERROR`를 반환해야 합니다.
부모 프로세스는 자식 프로세스의 복제 성공 여부를 알기 전까지
`fork()` 호출에서 반환되지 않아야 합니다.
- **자식 프로세스:** `0`을 반환합니다.
- **자원 복제:** 자식 프로세스는 **파일 디스크립터와 가상 메모리 공간을 포함한 모든 자원**을 복제해야 합니다.
- **레지스터 복제:** `%RBX`, `%RSP`, `%RBP`, `%R12` - `%R15`와 같은 **호출 수신자 저장(callee-saved) 레지스터**만 복제하면 됩니다.
- **구현 참고:** 제공된 템플릿은 `threads/mmu.c`의 `pml4_for_each()`를 사용하여 전체 사용자 메모리 공간과 페이지 테이블 구조를 복사합니다. 
`pte_for_each_func`의 누락된 부분을 채워야 합니다.
*/
static void
__do_fork (void *aux) {
	// process_init ();
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *child = thread_current();
	// current->parent = parent;

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = parent->parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	child->pml4 = pml4_create();
	if (child->pml4 == NULL)
		goto error;
	
	process_activate (child);
#ifdef VM
	supplemental_page_table_init (&child->spt);
	if (!supplemental_page_table_copy (&child->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) 
		goto error;
#endif
	/* TODO: 여기에 여러분의 코드를 작성하세요.
	 * TODO: 힌트) 파일 객체를 복제하려면, include/filesys/file.h에 있는
 	 * TODO: file_duplicate를 사용하세요. 부모 프로세스는
	 * TODO: 이 함수가 부모의 자원을 성공적으로 복제할 때까지
	 * TODO: fork()로부터 반환해서는 안 된다는 점에 유의하세요.*/
	// 부모의 td_table -> 자식 td_table

	bool filesys_lock_held = false;
	#ifdef USERPROG
		lock_acquire(&filesys_lock);
		filesys_lock_held = true;
		for (int fd = 2; fd < FD_MAX; fd++) {
			struct file* parent_file = parent->fd_table[fd];
			if (parent_file != NULL) {
				child->fd_table[fd] = file_duplicate(parent_file);
			}
		}
		lock_release(&filesys_lock);
		filesys_lock_held = false;
	#endif
	
	process_init ();
	/* Finally, switch to the newly created process. */
	if (succ) {
		sema_up(&child->fork_sema);
		do_iret (&if_);
	}
error:
	child->exit_status = -1;
	sema_up(&child->fork_sema);
	if (filesys_lock_held)
        lock_release(&filesys_lock);
	thread_exit ();
}

void user_stack_build(struct intr_frame* if_, int argc, char* argv_temp[]) {
	void* rsp = (void*) if_->rsp; // USER_STACK에서 시작
    char* argv_addrs[argc];

    // 1. 문자열 데이터 쌓기
    for (int i = argc - 1; i >= 0; i--) {
        int arg_len = strlen(argv_temp[i]) + 1;
        rsp -= arg_len;
        memcpy(rsp, argv_temp[i], arg_len);
        argv_addrs[i] = rsp;
    }

    // 2. 워드 정렬 패딩 쌓기 (문자열 다음, 주소 이전)
    int padding = (uintptr_t) rsp % 8;
    if (padding != 0) {
        rsp -= padding;
        memset(rsp, 0, padding);
    }

    // 3. NULL 포인터 센티널 쌓기 (argv[argc])
    rsp -= sizeof(char *);
    *((char **) rsp) = NULL;

    // 4. 문자열 주소(포인터) 쌓기
    for (int i = argc - 1; i >= 0; i--) {
        rsp -= sizeof(char *);
        *((char **) rsp) = argv_addrs[i];
    }

    // --- 최종 intr_frame 설정 ---
    
    // 이제 rsp는 argv 배열의 시작 주소를 가리킴. 이 값을 rsi에 설정.
	if_->R.rsi = (uint64_t) rsp;
    // argc 값을 rdi에 설정
	if_->R.rdi = argc;

    // 5. 가짜 반환 주소 쌓기
    rsp -= sizeof(void *);
    *((void **) rsp) = NULL;

    // 모든 작업이 끝난 후의 rsp 값을 intr_frame에 최종 설정
    if_->rsp = (uint64_t) rsp;

	// argc 값을 rdi에 설정
	if_->R.rdi = argc;
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */

 /* 
	1. 변수 준비: 인자의 개수(argc)와, 스택에 저장될 문자열들의 주소를 잠시 담아둘 argv_addrs 배열을 준비합니다.
	2. 문자열 데이터 쌓기: USER_STACK 꼭대기부터 시작해서, argv_temp에 있던 실제 문자열들("ls", "-l" 등)을 스택에 복사합니다. 
	복사할 때마다 스택 포인터(rsp)를 문자열 길이만큼 아래로 내리고, 복사된 위치의 주소를 argv_addrs에 기록합니다.
	3. 워드 정렬: 다음 데이터를 쌓기 전, 스택 포인터가 8의 배수 주소를 가리키도록 맞춥니다.
	4. 문자열 주소 쌓기: argv 배열을 만듭니다. NULL 센티널을 먼저 쌓고, 2번에서 기록해 둔 주소들을 역순으로 쌓습니다.
	5. 최종 인자 설정: main 함수가 받을 argc와 argv의 시작 주소를 각각 %rdi와 %rsi에 해당하는 _if 멤버에 설정합니다. 
	마지막으로 가짜 반환 주소를 쌓습니다.
	6. 최종 rsp 설정: 모든 짐을 다 실은 후의 마지막 위치를 실제 스택 포인터로 _if.rsp에 설정합니다.
	*/
int
process_exec (void *f_name) {
	char *file_name = f_name;
	char *save_ptr;
	char *delim = " ";
	char *argv_temp[MAX_BUFFER_SIZE];
	int argc = 0;

	char* copy_name = palloc_get_page(PAL_ZERO);
	if (copy_name == NULL) {
		return -1;
	}
	strlcpy(copy_name, f_name, PGSIZE);
	argv_temp[argc] = strtok_r(copy_name, delim, &save_ptr);

	/* And then load the binary */
	while (argv_temp[argc] != NULL) {
		argc++;
		argv_temp[argc] = strtok_r(NULL, delim, &save_ptr);
	}

	strlcpy(thread_current()->name, argv_temp[0], strlen(argv_temp[0]) + 1);

	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup(); // 기존 프로세스의 흔적을 지움

	/* If load failed, quit. */
	success = load (argv_temp[0], &_if); // 새로운 프로그램을 메모리에 적재함

	if (!success) {
		palloc_free_page(copy_name);
		return -1;
	}

	user_stack_build(&_if, argc, argv_temp);
	palloc_free_page(copy_name);

	// printf("--- Stack Dump for %s ---\n", argv_temp[0]);
    // hex_dump(_if.rsp, (void *)_if.rsp, USER_STACK - _if.rsp, true);
    // printf("--- Stack Dump End ---\n");

	/* Start switched process. */
	do_iret (&_if); //역할: 새로운 프로그램으로 제어권을 넘기는 최종 스위치
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread* child_thread = get_thread_by_tid(child_tid);
	struct thread* current_thread = thread_current();
	if (child_thread == NULL) {
		return -1;
	}
	// 찾은 자식 스레드의 세마포어에 sema_down() 호출
	sema_down(&child_thread->exit_sema);
	int status = child_thread->exit_status;
	// wait가 끝난 자식은 부모의 목록에서 제거 list_remove()
	list_remove(&child_thread->child_elem);
	// exit same up
	sema_up(&current_thread->wait_sema);

	return status;
}

/* Exit the process. This function is called by thread_exit (). */
// 1. parent에게 정보를 넘겨주기 전까지 죽지 않기 - sema 추가
// 2. parent에게 정보를 완전히 넘겨주기
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	#ifdef USERPROG
		/* 1. 열려있는 모든 파일들을 올바른 방법으로 닫기 */
		for (int i = 0; i < FD_MAX; i++) {
			if (curr->fd_table[i] != NULL) {
				file_close(curr->fd_table[i]);
			}
		}
		/* 2. fd_table 배열 자체의 메모리를 해제 */
		free(curr->fd_table);
	#endif

	// curr->parent->exit_status = curr->exit_status;
	sema_up(&curr->exit_sema);
	sema_down(&curr->wait_sema);
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open(file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
			
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
