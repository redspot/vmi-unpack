/*
 * Copyright (c) 2017 Carter Yagemann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TRACE_H
#define TRACE_H

#include <unistd.h>

typedef void (*assert_callable)(void *data);

//interrupt this process
inline void die(void *data) { kill(getpid(), SIGINT); }

#define my_assert_with_call_and_data(cond, mesg, call, data) \
    ({ \
        int __cond = (cond); \
        if ( __cond ) \
        { \
            fprintf(stderr, "%s\n", mesg); \
            assert_callable _call = call; \
            if (_call) _call(data); \
        } \
        __cond; \
    })

#define my_assert_with_call(cond, mesg, call) \
    my_assert_with_call_and_data(cond, mesg, call, 0)

#define my_assert_no_call(cond, mesg) \
    my_assert_with_call_and_data(cond, mesg, 0, 0)

#define GET_4TH_ARG(arg1, arg2, arg3, arg4, ...) arg4
#define MY_ASSERT_MACRO_CHOOSER(...) \
    GET_4TH_ARG(__VA_ARGS__, \
            my_assert_with_call_and_data, \
            my_assert_with_call, \
            my_assert_no_call, \
            )

#define my_assert(cond, mesg, ...) \
    MY_ASSERT_MACRO_CHOOSER(NULL, ##__VA_ARGS__)(cond, mesg, ##__VA_ARGS__)

#define STATIC_MESG_SIZE 256

#define make_static_mesg(fmt, ...) \
    ({ \
     char __mesg[STATIC_MESG_SIZE]={0}; \
	 snprintf(__mesg, sizeof(__mesg), \
			 "%s[%d]:"#fmt"\n" \
			 , __func__, __LINE__, ##__VA_ARGS__ \
			 ); \
     __mesg; \
     })


#define TRACE_STUFF
//#define TRACE_TRAPS
//#define TRACE_EXEC_TRAP
//#define TRACE_UNTRAP_VMA
//#define TRACE_TRAP_VMA
//#define TRACE_EXEC
//#define TRACE_WRITE
//#define TRACE_NTDLL
//#define TRACE_NTDLL_DEBUG1
//#define TRACE_NTDLL_DEBUG2

#ifdef TRACE_STUFF
#define trace(fmt, ...) \
    fprintf(stderr, \
    "%s[%d]:"#fmt"\n" \
    , __func__, __LINE__, ##__VA_ARGS__ \
    )
#else
#define trace(...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_TRAPS)
#define trace_trap(args...) trace(args)
#else
#define trace_trap(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_EXEC_TRAP)
#define trace_exec_trap(args...) trace(args)
#else
#define trace_exec_trap(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_UNTRAP_VMA)
#define trace_untrap_vma(args...) trace(args)
#else
#define trace_untrap_vma(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_TRAP_VMA)
#define trace_trap_vma(args...) trace(args)
#else
#define trace_trap_vma(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_EXEC)
#define trace_exec(args...) trace(args)
#else
#define trace_exec(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_WRITE)
#define trace_write(args...) trace(args)
#else
#define trace_write(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_NTDLL)
#define trace_ntdll(args...) trace(args)
#else
#define trace_ntdll(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_NTDLL_DEBUG1)
#define trace_ntdll_debug1(args...) trace(args)
#else
#define trace_ntdll_debug1(args...)
#endif

#if defined (TRACE_STUFF) && defined(TRACE_NTDLL_DEBUG2)
#define trace_ntdll_debug2(args...) trace(args)
#else
#define trace_ntdll_debug2(args...)
#endif

#endif
