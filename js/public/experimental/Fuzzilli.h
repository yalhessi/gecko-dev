#ifndef jit_Fuzzilli_h
#define jit_Fuzzilli_h

#  ifdef FUZZING_JS_FUZZILLI

#  define REPRL_CRFD 100
#  define REPRL_CWFD 101
#  define REPRL_DRFD 102
#  define REPRL_DWFD 103

#  define SHM_SIZE 0x100000
#  define MAX_EDGES ((SHM_SIZE - 4) * 8)

extern "C" uint32_t *__edges_start, *__edges_stop;

extern "C" uint32_t* __sanitizer_cov_next_available_guard();

extern "C" void __sanitizer_cov_reset_edgeguards();

extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* start,
                                                    uint32_t* stop);

extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t* guard);

#endif /* FUZZING_JS_FUZZILLI */
#endif /* jit_Fuzzilli_h */
