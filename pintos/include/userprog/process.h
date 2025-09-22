#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* 부모-자식 간 대기/종료 상태 공유 목적 */
// struct wait_status {
//     tid_t tid;                  /* 자식 tid */
//     int exit_status;            /* 자식 exit status */
//     int ref_cnt;                /* 참조 카운트(부모 1 + 자식 1 = 초기값 2) */
//     bool dead;                  /* 자식 종료 여부 */
//     struct semaphore sema;      /* 자식 종료 시 sema_up으로 부모를 깨움, 부모는 여기서 down */
//     struct list_elem elem;      /* 부모의 children 리스트에 들어갈 노드 */
// };

#endif /* userprog/process.h */
