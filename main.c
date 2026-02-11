#include "elf.h"
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#define MIN_ARG_COUNT 2

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
  //printf("??");

  off_t fsize = lseek(fd, 0, SEEK_END);
  __uint8_t *addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (addr == MAP_FAILED)
  {
    perror("mmap failed");
    return 1;
  }
  Elf64_Ehdr ehdr;
  memcpy(&ehdr, addr, sizeof(ehdr));
  int sht_i = 1;
  Elf64_Xword bss_size;
  Elf64_Shdr *sht_start = (Elf64_Shdr *)(addr + ehdr.e_shoff);

  while (sht_start[sht_i].sh_type != SHT_NOBITS)
  {
    sht_i++;
  }
  bss_size = sht_start[sht_i].sh_size;

  __uint8_t *baddr = (__uint8_t *)0;
  Elf64_Phdr *pht_start = (Elf64_Phdr *)(addr + ehdr.e_phoff);

  int pht_i = 1;
  while (pht_start[pht_i].p_type != PT_LOAD)
  {
    if (pht_start[pht_i].p_type == PT_INTERP)
    {
      *interpath = (char *)addr + pht_start[pht_i].p_offset;
    }
    pht_i++;
  };

  __uint8_t *map_addr;
  size_t prevfile__offset;
  // Note: This codes for PIE (ELF-DYN)
  Elf64_Phdr loadseg = pht_start[pht_i];
  prevfile__offset = loadseg.p_offset;
  // NB:loadseg.p_filesz must be a multiple of sysconf(SC_PAGE_SIZE)
  size_t mmap_length = loadseg.p_filesz;
  // file mapping is not enough, .bss tailed loadsegment
  // TOD0: handle .bss tailed loadsegment as some shares a page with previous load segments
  // Any loadable segment , that have a page_aligned offset is a file page and hence needs to have a corresponding virtual memory page
  // JUst found that, loadable segments can share memory pages/memory mappings see the fourth segment in readelf -lf main
  mmap_length = ((mmap_length + 0) + page_size - 1) & ~(page_size - 1);
  // Perhaps we need to choose a lower memory address and be intentional about about the starting addresses of our virtual memory areas to prevent clobbering(text,data,stack etc)
  map_addr = mmap((void *)0x08048000, loadseg.p_filesz, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE, fd, loadseg.p_offset);
  if (map_addr == MAP_FAILED)
  {
    perror("mmap failed:mapping the lowest file page");
    return 1;
  }

  baddr = map_addr - (((loadseg.p_offset + page_size) - 1) & ~(page_size - 1));
  __uint8_t *p_entry = baddr + ehdr.e_entry;

  pht_i++;
  for (; pht_i < ehdr.e_phnum; pht_i++)
  {
    loadseg = pht_start[pht_i];
    if (pht_start[pht_i].p_type != PT_LOAD)
      continue;

    size_t mmap_length = loadseg.p_filesz;
    size_t mmap_offset = loadseg.p_offset;

    // file mapping is not enough, .bss tailed loadsegment
    // TOD0: handle .bss tailed loadsegment as some shares a page with previous load segments
    if (loadseg.p_memsz > loadseg.p_filesz)
    {
      // if...p_offset is not page_align...it means it exists in the most recent mapping
      //  now the question...did it cover all file_sz??if yes, we don't need a new mapping if no..we need a new mapping
      //  if p_offset nearest page(the page it was meant to be) is > than p_offset + file_size + bss_size if yes, we don't need a new mapping, then we zero initialize bss starting from p_offset + file_size
      //  We create a  new mapping from p_offset nearest page , with length (p_offset_nearest_page - (p_offset + file_size + bss_size))
      // after, we zero initialize bss starting from p_offset + file_size
      // load_segments with a page_aligned offset, requires a corresponding mapping. one file page -> one memory page
      if (loadseg.p_offset % page_size == 0)
      {
        map_addr = baddr + loadseg.p_offset;
        map_addr = mmap(map_addr, mmap_length + bss_size, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE | MAP_FIXED, fd, mmap_offset);

        if (map_addr == MAP_FAILED)
        {
          perror("mmap failed:mapping a file page");
          return 1;
        }
        memset(map_addr + loadseg.p_filesz, '\0', bss_size);
      }
      else
      {
        // Already covered by a mapping, but by how much??
        __int8_t *start = (__int8_t *)((size_t)baddr + ((mmap_offset + page_size - 1) & ~(page_size - 1)));
        // distance between two load segs in file
        Elf64_Off distance = (loadseg.p_offset - prevfile__offset);
        __int8_t *end = (__int8_t *)((size_t)map_addr + distance + loadseg.p_filesz + bss_size);
        // pt_load_cnts++;
        //*vmaddr_ptr++ = ((Elf64_Addr)map_addr + distance);
        //*fpaddr_ptr++ = (Elf64_Addr)loadseg.p_offset;
        if (end < start)
        {
          memset(map_addr + distance + loadseg.p_filesz, '\0', bss_size);
          continue;
        }
        else
        {
          __int8_t *bss_start = map_addr + distance + loadseg.p_filesz;
          // we need a new mapping
          map_addr = baddr + ((mmap_offset + page_size - 1) & ~(page_size - 1));
          map_addr = mmap(map_addr, end - start, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE | MAP_FIXED, fd, ((mmap_offset + page_size - 1) & ~(page_size - 1)));
          if (map_addr == MAP_FAILED)
          {
            perror("mmap failed:mapping a file page");
            return 1;
          }
          memset(bss_start, '\0', bss_size);
        }
      }
    }
    else
    {
      // if...p_offset is not page_align...it means it exists in the most recent mapping
      //  now the question...did it cover all file_sz??if yes, we don't need a new mapping if no..we need a new mapping
      //  if p_offset nearest page(the page it was meant to be) is > than p_offset + file_size + bss_size if yes, we don't need a new mapping, then we zero initialize bss starting from p_offset + file_size
      //  We create a  new mapping from p_offset nearest page , with length (p_offset_nearest_page - (p_offset + file_size + bss_size))
      // after, we zero initialize bss starting from p_offset + file_size
      // load_segments with a page_aligned offset, requires a corresponding mapping. one file page -> one memory page
      if (loadseg.p_offset % page_size == 0)
      {
        map_addr = baddr + loadseg.p_offset;
        map_addr = mmap(map_addr, mmap_length, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE | MAP_FIXED, fd, mmap_offset);

        if (map_addr == MAP_FAILED)
        {
          perror("mmap failed:mapping a file page");
          return 1;
        }
      }
      else
      {
        // Already covered by a mapping, but by how much??
        __int8_t *start = (__int8_t *)((size_t)baddr + ((mmap_offset + page_size - 1) & ~(page_size - 1)));
        // distance between two load segs in file
        Elf64_Off distance = (loadseg.p_offset - prevfile__offset);
        __int8_t *end = (__int8_t *)((size_t)map_addr + distance + loadseg.p_filesz + 0);
        if (end < start)
          continue;
        else
        {
          __int8_t *bss_start = map_addr + distance + loadseg.p_filesz;
          // we need a new mapping
          map_addr = baddr + ((mmap_offset + page_size - 1) & ~(page_size - 1));
          map_addr = mmap(map_addr, (Elf64_Addr)end - (Elf64_Addr)start, elf_pflags_to_mmap_prot((int)loadseg.p_flags), MAP_PRIVATE | MAP_FIXED, fd, ((mmap_offset + page_size - 1) & ~(page_size - 1)));
          if (map_addr == MAP_FAILED)
          {
            perror("mmap failed:mapping a file page");
            return 1;
          }
        }
      }
      prevfile__offset = loadseg.p_offset;
    }
  }
  close(fd);
  // setup stack
  // setup a memory image for program interpretor
  //  jump to _start
  return 0;
}

// Usage ./loader <path-to-elf-file> [CLI args to be passed to during process
// execution of the program]
int main(int argc, char **args)
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
    printf("%s\n", interpath);
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