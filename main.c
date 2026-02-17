#include "elf.h"
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>

#define MIN_ARG_COUNT 2

typedef struct
{
  int argc;
  int envc;
  __uint8_t *envp;
  __int8_t *argp;

} Usr_bckd_stck;

static int elf_pflags_to_mmap_prot(int p_flags)
{
  int prot = 0;

  if (p_flags & PF_R)
    prot |= PROT_READ;
  if (p_flags & PF_W)
    prot |= PROT_WRITE;
  if (p_flags & PF_X)
    prot |= PROT_EXEC;

  return prot;
}
// function used to load executable files, shared objects like program interp
int LoadET(int fd, size_t page_size, char **interpath)
{

  off_t fsize = lseek(fd, 0, SEEK_END);
  __uint8_t *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;
  Elf64_Phdr *pht_start = (Elf64_Phdr *)(addr + ehdr->e_phoff);
  int pht_i = 1;
  Elf64_Addr max_vaddr = 0;
  Elf64_Addr min_vaddr = 0;
  size_t loadsegmmap_len = 0;
  int loagseg_i[__UINT8_MAX__] = {0};
  for (; pht_i < ehdr->e_phnum; pht_i++)
  {
    if (pht_start[pht_i].p_type == PT_INTERP)
    {
      //
    } // else if (pht_start[pht_i].p_type == PT_GNU_STACK){
    // check to add PROT_EXEC to stack page
    // }
    else if (pht_start[pht_i].p_type == PT_LOAD)
    {
      if (pht_start[pht_i].p_vaddr > max_vaddr)
      {
        max_vaddr = pht_start[pht_i].p_vaddr;
        loadsegmmap_len = pht_start[pht_i].p_vaddr + pht_start[pht_i].p_memsz;
        loagseg_i[pht_i] = pht_i;
      }
      else if (pht_start[pht_i].p_vaddr <= min_vaddr)
        min_vaddr = pht_start[pht_i].p_vaddr;
    }
  }
  pht_i = 1;
  // now we reserve region
  __uint8_t *segs_addr = mmap(NULL, loadsegmmap_len, PROT_NONE, MAP_PRIVATE, -1, 0);
  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }
  __uint8_t *baddr = segs_addr - min_vaddr;
  for (; pht_i < __UINT8_MAX__; pht_i++)
  {
    if (loagseg_i[pht_i] == 0)
      continue;

    Elf64_Off relap_offset = pht_start[pht_i].p_offset & ~(page_size - 1);
    Elf64_Addr relap_vadress = pht_start[pht_i].p_vaddr & ~(page_size - 1);
    mmap(baddr + relap_vadress, (pht_start[pht_i].p_vaddr % page_size) + pht_start[pht_i].p_filesz, elf_pflags_to_mmap_prot(pht_start[pht_i].p_flags), MAP_PRIVATE | MAP_FIXED, fd, relap_offset);
    if (addr == MAP_FAILED)
    {
      perror("mmap failed");
      return 1;
    }
    if (pht_start[pht_i].p_memsz > pht_start[pht_i].p_filesz)
    {
      size_t bss_size = pht_start[pht_i].p_memsz - pht_start[pht_i].p_filesz;
      memset(baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz, '\0', bss_size);
      // TODO: set the program break at baddr + pht_start[pht_i].p_vaddr + pht_start[pht_i].p_filesz + bss_size
      // Heap allocation grows continously and fails when there's already an existing mapping in that range
      // need to make sure where we load the interp are thousands of pages away
    }
  }

  close(fd);
  munmap(addr, fsize);
  return 0;
}

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args, char **envp)
{
  pid_t childpid = 0;

  if (argc < MIN_ARG_COUNT)
    return 1;

  const char *elfpath = args[1];
  int fd = open(elfpath, O_RDONLY);

  size_t page_size = sysconf(_SC_PAGE_SIZE);

  if ((childpid = fork()) == 0)
  {
    char *interpath = NULL;
    int status = LoadET(fd, page_size, &interpath);
    // TODO: randomize the highest address of the stack
    __uint8_t *stackTop = (__uint8_t *)0x7fff6c845000;
    struct rlimit lm;
    size_t stack_max_size = getrlimit(RLIMIT_STACK, &lm);
    __uint8_t *stackEnd = (size_t)0x7fff6c845000 - (stack_max_size & ~(page_size - 1));

    Usr_bckd_stck stck = {0};
    stck.argc = argc - 1;

    int cpy_i;

    char **t_args = args;
    char **t_envp = envp;
    // we skip the name of the executable file
    t_args++;
    size_t t_args_size = 0;
    while (*t_args)
    {
      t_args_size = t_args_size + (strlen(*t_args) + 1);
      t_args++;
    }

    size_t t_env_size = 0;
    while (*t_envp)
    {
      t_envp = t_env_size + (strlen(*t_envp) + 1);
      stck.envc++;
      t_envp++;
    }
    __uint8_t *temp = (__uint8_t *)malloc(sizeof(Usr_bckd_stck) + t_args_size + t_env_size);
    if (temp == NULL)
    {
      perror("Temporal memory allocation to hold userspace, argc,args and envp failed");
      return 1;
    };

    // copy args
    for (cpy_i = 1; cpy_i < stck.argc; cpy_i++)
    {
      memcpy(temp + sizeof(Usr_bckd_stck), args[cpy_i], t_args_size);
    }
    // copy env
    for (cpy_i = 0; cpy_i < stck.envc; cpy_i++)
    {
      memcpy(temp + sizeof(Usr_bckd_stck) + t_args_size, envp[cpy_i], t_env_size);
    }
    Usr_bckd_stck *stckptr = temp;
    stckptr->argc = stck.argc;
    stckptr->envc = stck.envc;
    stckptr->argp = stckptr + sizeof(Usr_bckd_stck);
    stckptr->envp = stckptr->argp + t_args_size;
    // We are turning this child process into a process that executes <path-to-elf-file> [CLI args to be passed to during process. so MAP_FIXED | MAP_PRIVATE or MAP_PRIVATE
    // Currently our stack have the necessary information we are trying to copy

    return status;
  }

  /* If we forked above, wait for the child so the parent suspends until child exits. */
  if (childpid > 0)
  {
    int status = 0;
    if (waitpid(childpid, &status, 0) == -1)
    {
      perror("waitpid failed");
      return 1;
    }
    if (WIFEXITED(status))
      return WEXITSTATUS(status);
    return 0;
  }

  return 0;
}