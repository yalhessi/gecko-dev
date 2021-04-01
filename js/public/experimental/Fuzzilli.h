#ifndef jit_Fuzzilli_h
#define jit_Fuzzilli_h

#include "js/experimental/Fuzzilli.h"
#  ifdef FUZZING_JS_FUZZILLI

#include <algorithm>
#include <chrono>

#ifdef XP_WIN
#  include <direct.h>
#  include <process.h>
#endif

#include <errno.h>
#include <fcntl.h>

#if defined(XP_WIN)
#  include <io.h> /* for isatty() */
#endif

#include <locale.h>

#if defined(MALLOC_H)
#  include MALLOC_H /* for malloc_usable_size, malloc_size, _msize */
#endif

#include <ctime>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <utility>

#ifdef XP_UNIX
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#ifdef XP_LINUX
#  include <sys/prctl.h>
#endif

#include "jsapi.h"
#include "jsfriendapi.h"
#include "jstypes.h"

#ifndef JS_WITHOUT_NSPR
#  include "prerror.h"
#  include "prlink.h"
#endif



#  define REPRL_CRFD 100
#  define REPRL_CWFD 101
#  define REPRL_DRFD 102
#  define REPRL_DWFD 103

#  define SHM_SIZE 0x100000
#  define MAX_EDGES ((SHM_SIZE - 4) * 8)

struct shmem_data {
  uint32_t num_edges;
  unsigned char edges[];
};

struct shmem_data* __shmem;

uint32_t *__edges_start, *__edges_stop;

uint32_t* __sanitizer_cov_next_available_guard() {
if (__edges_stop - __edges_stop < MAX_EDGES) {
  __shmem->num_edges++;
  return __edges_stop++;
}
return __edges_stop;
}

void __sanitizer_cov_reset_edgeguards() {
  uint64_t N = 0;
  for (uint32_t* x = __edges_start; x < __edges_stop && N < MAX_EDGES; x++)
    *x = ++N;
}

extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* start,
                                                    uint32_t* stop) {
  // Avoid duplicate initialization
  if (start == stop || *start) return;

  if (__edges_start != NULL || __edges_stop != NULL) {
    fprintf(stderr,
            "Coverage instrumentation is only supported for a single module\n");
    _exit(-1);
  }

  // stop += 10000; // add some extra edges for generated code

  __edges_start = start;
  __edges_stop = stop;

  // Map the shared memory region
  const char* shm_key = getenv("SHM_ID");
  if (!shm_key) {
    puts("[COV] no shared memory bitmap available, skipping");
    __shmem = (struct shmem_data*)malloc(SHM_SIZE);
  } else {
    int fd = shm_open(shm_key, O_RDWR, S_IREAD | S_IWRITE);
    if (fd <= -1) {
      fprintf(stderr, "Failed to open shared memory region: %s\n",
              strerror(errno));
      _exit(-1);
    }

    __shmem = (struct shmem_data*)mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE,
                                       MAP_SHARED, fd, 0);
    if (__shmem == MAP_FAILED) {
      fprintf(stderr, "Failed to mmap shared memory region\n");
      _exit(-1);
    }
  }

  __sanitizer_cov_reset_edgeguards();

  __shmem->num_edges = stop - start;
  printf("[COV] edge counters initialized. Shared memory: %s with %u edges\n",
         shm_key, __shmem->num_edges);
}

extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  // There's a small race condition here: if this function executes in two
  // threads for the same edge at the same time, the first thread might disable
  // the edge (by setting the guard to zero) before the second thread fetches
  // the guard value (and thus the index). However, our instrumentation ignores
  // the first edge (see libcoverage.c) and so the race is unproblematic.
  uint32_t index = *guard;
  // If this function is called before coverage instrumentation is properly
  // initialized we want to return early.
  if (!index) return;
  __shmem->edges[index / 8] |= 1 << (index % 8);
  *guard = 0;
}

#endif /* FUZZING_JS_FUZZILLI */
#endif /* jit_Fuzzilli_h */
