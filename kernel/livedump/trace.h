/* SPDX-License-Identifier: GPL-2.0-or-later */

/* livedump/trace.h */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM livedump

#if !defined(_TRACE_LIVEDUMP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LIVEDUMP_H

#include <linux/blk_types.h>
#include <linux/tracepoint.h>

#define CREATE_LIVEDUMP_TRACE(name) \
TRACE_EVENT(livedump_##name,		\
	TP_PROTO(int dummy),			\
	TP_ARGS(dummy),					\
	TP_STRUCT__entry(				\
		__field(int, dummy)			\
	),								\
	TP_fast_assign(					\
		__entry->dummy = dummy;		\
	),								\
	TP_printk("%s", "")				\
)

CREATE_LIVEDUMP_TRACE(pre_init);
CREATE_LIVEDUMP_TRACE(post_init);
CREATE_LIVEDUMP_TRACE(pre_start);
CREATE_LIVEDUMP_TRACE(post_start);
CREATE_LIVEDUMP_TRACE(pre_sweep);
CREATE_LIVEDUMP_TRACE(post_sweep);
CREATE_LIVEDUMP_TRACE(finish);
CREATE_LIVEDUMP_TRACE(uninit);


/* memdump trace */
TRACE_EVENT(livedump_handle_page,
	TP_PROTO(unsigned long pfn, unsigned long pend_len, bool for_sweep),
	TP_ARGS(pfn, pend_len, for_sweep),
	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(unsigned long, pend_len)
		__field(bool, for_sweep)
	),
	TP_fast_assign(
		__entry->pfn = pfn;
		__entry->pend_len = pend_len;
		__entry->for_sweep = for_sweep;
	),
	TP_printk("pfn=%lu, pend_len=%lu, sweep=%d", __entry->pfn,
		__entry->pend_len, __entry->for_sweep)
);

TRACE_EVENT(livedump_handle_page_finished,
	TP_PROTO(unsigned long pfn, bool for_sweep),
	TP_ARGS(pfn, for_sweep),
	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(bool, for_sweep)
	),
	TP_fast_assign(
		__entry->pfn = pfn;
		__entry->for_sweep = for_sweep;
	),
	TP_printk("pfn=%lu, sweep=%d", __entry->pfn, __entry->for_sweep)
);

#endif /* _TRACE_LIVEDUMP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../kernel/livedump/
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
