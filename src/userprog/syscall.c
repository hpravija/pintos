#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define WRITE_STDOUT 1

static void syscall_handler (struct intr_frame *);
static int sys_write (int fd, const void* buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_type = *(int *) f->esp;
 
  switch (syscall_type)
  {
  case SYS_EXIT:
  {
    int status = *((int *) f->esp + 1);
    struct thread *t = thread_current();
    t->exit_status = status;
    thread_exit();
    printf("%s: exit(%d)\n", t->name, status);
  }
  case SYS_WRITE:
  {
    int fd = *((int *) f->esp + 1);
    void *buffer = (void *) (*((int *) f->esp + 2));
    unsigned size = *(unsigned *) (((int *) f->esp + 3));
    f->eax = sys_write(fd, buffer, size);
    break;  
  }

  default:
    break;
  }
}

static int sys_write (int fd, const void* buffer, unsigned size)
{
  char *buffer_cpy = (char*) buffer;
  int _size = 0;

  if (fd == WRITE_STDOUT)
  {
    putbuf(buffer_cpy, size);
    _size = size;
  }
  else {
  }

  return _size;
}