/*
 * Copyright 2010-2018, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * API and basic usage
 * -------------------
 *
 * The following example demonstrates API of the module:
 *
 * ```
 * local net_box = require('net.box')
 * local buffer = require('buffer')
 * local merger = require('merger')
 *
 * -- The format of key_parts parameter is the same as
 * -- `{box,conn}.space.<...>.index.<...>.parts` (where conn is
 * -- net.box connection).
 * local key_parts = {
 *     {
 *         fieldno = <number>,
 *         type = <string>,
 *         [ is_nullable = <boolean>, ]
 *         [ collation_id = <number>, ]
 *         [ collation = <string>, ]
 *     },
 *     ...
 * }
 *
 * -- Create the merger instance.
 * local merger_inst = merger.new(key_parts)
 *
 * -- Optional parameters.
 * local opts = {
 *     -- Output buffer, only for merger_inst:select(<...>).
 *     [ buffer = <buffer>, ]
 *     -- Ascending (default) or descending result order.
 *     [ descending = <boolean>, ]
 *     -- Buffer encoding / decoding options are described below.
 *     [ decode = 'raw' / 'select' / 'call' / 'chain', ]
 *     [ encode = 'raw' / 'select' / 'call' / 'chain', ]
 *     [ encode_chain_len = <number>, ]
 * }
 *
 * -- Prepare buffer source.
 * local conn = net_box.connect('localhost:3301')
 * local buf = buffer.ibuf()
 * conn.space.s:select(nil, {buffer = buf}) -- read to buffer
 *
 * -- We have three sources here.
 * local sources = {
 *     buf,                   -- buffer source
 *     box.space.s:select(),  -- table source
 *     {box.space.s:pairs()}, -- iterator source
 * }
 *
 * -- Read the whole result at once.
 * local res = merger_inst:select(sources, opts)
 *
 * -- Read the result tuple per tuple.
 * local res = {}
 * for _, tuple in merger_inst:pairs(sources, opts) do
 *     -- Some stop merge condition.
 *     if tuple[1] > MAX_VALUE then break end
 *     table.insert(res, tuple)
 * end
 *
 * -- The same in the functional style.
 * local function cond(tuple)
 *     return tuple[1] <= MAX_VALUE
 * end
 * local res = merger_inst:pairs(sources, opts):take(cond):totable()
 * ```
 *
 * The basic case of using merger is when there are M storages and
 * data are partitioned (sharded) across them. A client want to
 * fetch the data (tuples stream) from each storage and merge them
 * into one tuple stream:
 *
 * ```
 * local net_box = require('net.box')
 * local buffer = require('buffer')
 * local merger = require('merger')
 *
 * -- Prepare M sources.
 * local connects = {
 *     net_box.connect('localhost:3301'),
 *     net_box.connect('localhost:3302'),
 *     ...
 *     net_box.connect('localhost:<...>'),
 * }
 * local sources = {}
 * for _, conn in ipairs(connects) do
 *     local buf = buffer.ibuf()
 *     conn.space.<...>.index.<...>:select(<...>, {buffer = buf})
 *     table.insert(sources, buf)
 * end
 *
 * -- See the 'Notes...' section below.
 * local key_parts = {}
 * local space = connects[1].space.<...>
 * local index = space.index.<...>
 * for _, part in ipairs(index.parts) do
 *     table.insert(key_parts, part)
 * end
 * if not index.unique then
 *     for _, part in ipairs(space.index[0]) do
 *         table.insert(key_parts, part)
 *     end
 * end
 *
 * -- Create the merger instance.
 * local merger_inst = merger.new(key_parts)
 *
 * -- Merge.
 * local res = merger_inst:select(sources)
 * ```
 *
 * Notes re source sorting and key parts
 * -------------------------------------
 *
 * The merger expects that each source tuples stream is sorted
 * according to provided key parts and perform a kind of merge
 * sort (choose minimal / maximal tuple across sources on each
 * step). Tuples from select() from Tarantool's space are sorted
 * according to key parts from index that was used. When secondary
 * non-unique index is used tuples are sorted according to the key
 * parts of the secondary index and, then, key parts of the
 * primary index.
 *
 * Decoding / encoding buffers
 * ---------------------------
 *
 * A select response has the following structure:
 * `{[48] = {tuples}}`, while a call response is
 * `{[48] = {{tuples}}}` (because it should support multiple
 * return values). A user should specify how merger will
 * operate on buffers, so merger has `decode` (how to read buffer
 * sources) and `encode` (how to write to a resulting buffer)
 * options. These options accept the following values:
 *
 * Option value       | Buffer structure
 * ------------------ | ----------------
 * 'raw'              | tuples
 * 'select' (default) | {[48] = {tuples}}
 * 'call'             | {[48] = {{tuples}}}
 * 'chain'            | {[48] = {{{tuples, ...}}}}
 *
 * tuples is array of tuples. 'raw' and 'chain' options are about chaining
 * mergers and they are described in the following section.
 *
 * How to check buffer data structure myself:
 *
 * ```
 * #!usr/bin/env tarantool
 *
 * local net_box = require('net.box')
 * local buffer = require('buffer')
 * local ffi = require('ffi')
 * local msgpack = require('msgpack')
 * local yaml = require('yaml')
 *
 * box.cfg{listen = 3301}
 * box.once('load_data', function()
 *     box.schema.user.grant('guest', 'read,write,execute', 'universe')
 *     box.schema.space.create('s')
 *     box.space.s:create_index('pk')
 *     box.space.s:insert({1})
 *     box.space.s:insert({2})
 *     box.space.s:insert({3})
 *     box.space.s:insert({4})
 * end)
 *
 * local function foo()
 *     return box.space.s:select()
 * end
 * _G.foo = foo
 *
 * local conn = net_box.connect('localhost:3301')
 *
 * local buf = buffer.ibuf()
 * conn.space.s:select(nil, {buffer = buf})
 * local buf_str = ffi.string(buf.rpos, buf.wpos - buf.rpos)
 * local buf_lua = msgpack.decode(buf_str)
 * print('select:\n' .. yaml.encode(buf_lua))
 *
 * local buf = buffer.ibuf()
 * conn:call('foo', nil, {buffer = buf})
 * local buf_str = ffi.string(buf.rpos, buf.wpos - buf.rpos)
 * local buf_lua = msgpack.decode(buf_str)
 * print('call:\n' .. yaml.encode(buf_lua))
 *
 * os.exit()
 * ```
 *
 * The `decode` option changes decoding algorithm of source
 * buffers and does nothing for sources of other types. It will be
 * completely ignored if there are no buffer sources.
 *
 * The `encode` option changes encoding algorithm of resulting
 * buffer. When the option is provided, the `buffer` option should
 * be provided too. When `encode` is 'chain', the
 * `encode_chain_len` option is mandatory.
 *
 * Chaining mergers
 * ----------------
 *
 * Chaining mergers is needed to process a batch select request,
 * when one response (buffer) contains several results (tuple
 * arrays) to merge with another responses of this kind. Reshaping
 * of such results into separate buffers or lua table would lead
 * to extra data copies within Lua memory and extra time consuming
 * msgpack decoding, so the merger supports this case of source
 * data shape natively.
 *
 * When the `decode` option is 'select' (or nil) or 'call' the
 * merger expects a usual net.box's select / call result in each
 * of source buffers.
 *
 * When the `decode` option is 'chain' or 'raw' the merger expects
 * an array of results instead of just result. Pass 'chain' for
 * the first `:select()` (or `:pairs()`) call and 'raw' for the
 * following ones. It is possible (but not mandatory) to use
 * different mergers for each result, just reuse the same buffers
 * for consequent calls.
 *
 * ```
 * -- Storage script
 * -- --------------
 *
 * -- Return N results in a table.
 * -- Each result is table of tuples.
 * local function batch_select(<...>)
 *     local res = {}
 *     for i = 1, N do
 *         local tuples = box.space.<...>:select(<...>)
 *         table.insert(res, tuples)
 *     end
 *     return res
 * end
 *
 * -- Expose to call it using net.box.
 * _G.batch_select = batch_select
 *
 * -- Client script
 * -- -------------
 *
 * local net_box = require('net.box')
 * local buffer = require('buffer')
 * local merger = require('merger')
 *
 * -- Prepare M sources.
 * local connects = <...>
 * local sources = {}
 * for _, conn in ipairs(connects) do
 *     local buf = buffer.ibuf()
 *     conn:call('batch_select', <...>, {buffer = buf})
 *     table.insert(sources, buf)
 * end
 *
 * -- Now we have M sources and each have N results. We want to
 * -- merge all 1st results, all 2nd results, ..., all Nth
 * -- results.
 *
 * local merger_inst = merger.new(<...>)
 *
 * local res = {}
 * for i = 1, N do
 *     -- We use the same merger instance for each merge, but it
 *     -- is possible to use different ones.
 *     local tuples = merger_inst:select(sources, {
 *         decode = i == 1 and 'chain' or 'raw',
 *     })
 *     table.insert(res, tuples)
 * end
 * ```
 *
 * When `buffer` option is passed it is possible to write results
 * of several consequent merges into that buffer in the format
 * another merger can accept (see cascading mergers below for the
 * idea). Set `encode` to 'chain' to encode the first result
 * and to 'raw' to encode consequent results. It is necessary to
 * also set `encode_chain_len`, because size of resulting array
 * is not known to a merger when it writes the first result.
 *
 * Constraints are:
 *
 * - `decode` option influences only on buffer sources
 *   interpretation (ignored for sources of other types).
 * - `encode_*` options are applicable only when `buffer`
 *   options is provided.
 *
 * Cascading mergers
 * -----------------
 *
 * The idea is simple: the merger output formats are the same as
 * source formats, so it is possible to merge results of previous
 * merges.
 *
 * The example below is synthetic to be simple. Real cases when
 * cascading can be profitable likely involve additional layers
 * of Tarantool instances between storages and clients or separate
 * threads to merge blocks of each level.
 *
 * To be honest no one use this ability for now. It exists,
 * because the same input and output formats looks as good
 * property of the API.
 *
 * ```
 * <...requires...>
 *
 * local sources = <...100 buffers...>
 * local merger_inst = merger.new(<...>)
 *
 * -- We use buffer sources at 1st and 2nd merge layers, but read
 * -- the final result as the table.
 *
 * local sources_level_2 = {}
 * for i = 1, 10 do
 *     -- Take next 10 first level sources.
 *     local sources_level_1 = {}
 *     for j = 1, 10 do
 *         sources_level_1[j] = sources[(i - 1) * 10 + j]
 *     end
 *
 *     -- Merge 10 sources into a second level source.
 *     local result_level_1 = buffer.ibuf()
 *     merger_inst:select(sources_level_1, {buffer = result_level_1})
 *     sources_level_2[i] = result_level_1
 * end
 *
 * local res = merger_inst:select(sources_level_2)
 * ```
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <lua.h>
#include <lauxlib.h>

#include "lua/utils.h"
#include "small/ibuf.h"
#include "msgpuck.h"
#include "msgpack.h"

#define HEAP_FORWARD_DECLARATION
#include "salad/heap.h"

#include "box/iproto_constants.h" /* IPROTO_DATA */
#include "box/field_def.h"
#include "box/key_def.h"
#include "box/schema_def.h"
#include "box/tuple.h"
#include "box/lua/tuple.h"
#include "box/box.h"
#include "box/index.h"
#include "box/coll_id_cache.h"
#include "lua/lua_iterator.h"
#include "diag.h"

#ifndef NDEBUG
#include "say.h"
/**
 * Heap insert/delete/update macros wrapped with debug prints.
 */
#define MERGER_HEAP_INSERT(heap, hnode, source) do {			\
	say_debug("merger: [source %p] insert: tuple: %s", (source),	\
		  tuple_str((source)->tuple));				\
	merger_heap_insert((heap), (hnode));				\
} while(0)
#define MERGER_HEAP_DELETE(heap, hnode, source) do {		\
	say_debug("merger: [source %p] delete", (source));	\
	merger_heap_delete((heap), (hnode));			\
} while(0)
#define MERGER_HEAP_UPDATE(heap, hnode, source) do {			\
	say_debug("merger: [source %p] update: tuple: %s", (source),	\
		  tuple_str((source)->tuple));				\
	merger_heap_update((heap), (hnode));				\
} while(0)
#else /* !defined(NDEBUG) */
/**
 * Heap insert/delete/update macros wrappers w/o debug prints.
 */
#define MERGER_HEAP_INSERT(heap, hnode, source) do {	\
	merger_heap_insert((heap), (hnode));		\
} while(0)
#define MERGER_HEAP_DELETE(heap, hnode, source) do {	\
	merger_heap_delete((heap), (hnode));		\
} while(0)
#define MERGER_HEAP_UPDATE(heap, hnode, source) do {	\
	merger_heap_update((heap), (hnode));		\
} while(0)
#endif /* !defined(NDEBUG) */

/**
 * Helper macros to push / throw out of memory errors to Lua.
 */
#define push_out_of_memory_error(L, size, what_name) do {	\
	diag_set(OutOfMemory, (size), "malloc", (what_name));	\
	luaT_pusherror(L, diag_last_error(diag_get()));		\
} while(0)
#define throw_out_of_memory_error(L, size, what_name) do {	\
	diag_set(OutOfMemory, (size), "malloc", (what_name));	\
	luaT_error(L);						\
	unreachable();						\
	return -1;						\
} while(0)

#define BOX_COLLATION_NAME_INDEX 1

/**
 * A type of data structure that holds source data.
 */
enum merger_source_type {
	SOURCE_TYPE_BUFFER,
	SOURCE_TYPE_TABLE,
	SOURCE_TYPE_ITERATOR,
	SOURCE_TYPE_NONE,
};

/**
 * How data are encoded in a buffer.
 *
 * `decode` and `encode` options are parsed to values of this
 * enum.
 */
enum merger_buffer_type {
	BUFFER_TYPE_RAW,
	BUFFER_TYPE_SELECT,
	BUFFER_TYPE_CALL,
	BUFFER_TYPE_CHAIN,
	BUFFER_TYPE_NONE,
};

/**
 * Hold state of a merge source.
 */
struct merger_source {
	/*
	 * A source is the heap node. Compared by the next tuple.
	 */
	struct heap_node hnode;
	/* Union determinant. */
	enum merger_source_type type;
	/* Fields specific for certaint source types. */
	union {
		/* Buffer source. */
		struct {
			struct ibuf *buf;
			/*
			 * A merger stops before end of a buffer
			 * when it is not the last merger in the
			 * chain.
			 */
			size_t remaining_tuples_cnt;
		} buf;
		/* Table source. */
		struct {
			int ref;
			int next_idx;
		} tbl;
		/* Iterator source. */
		struct {
			struct lua_iterator *it;
		} it;
	};
	/* Next tuple. */
	struct tuple *tuple;
};

/**
 * Holds immutable parameters of a merger.
 */
struct merger {
	struct key_def *key_def;
	box_tuple_format_t *format;
};

/**
 * Holds parameters of merge process, sources, result storage
 * (if any), heap of sources and utility flags / counters.
 */
struct merger_iterator {
	/* Heap of sources. */
	heap_t heap;
	/*
	 * key_def is copied from merger.
	 *
	 * A merger can be collected by LuaJIT GC independently
	 * from a merger_iterator, so we cannot just save pointer
	 * to merger here and so we copy key_def from merger.
	 */
	struct key_def *key_def;
	/* Parsed sources and decoding parameters. */
	uint32_t sources_count;
	struct merger_source **sources;
	enum merger_buffer_type decode;
	/* Ascending / descending order. */
	int order;
	/* Optional output buffer and encoding parameters. */
	struct ibuf *obuf;
	enum merger_buffer_type encode;
	uint32_t encode_chain_len;
};

static uint32_t merger_type_id = 0;
static uint32_t merger_iterator_type_id = 0;
static uint32_t ibuf_type_id = 0;

/* Forward declarations. */
static bool
source_less(const heap_t *heap, const struct heap_node *a,
	    const struct heap_node *b);
static int
lbox_merger_gc(struct lua_State *L);
static void
merger_iterator_delete(struct lua_State *L, struct merger_iterator *it);
static int
lbox_merger_iterator_gc(struct lua_State *L);

#define HEAP_NAME merger_heap
#define HEAP_LESS source_less
#include "salad/heap.h"

/**
 * Create the new tuple with specific format from a Lua table or a
 * tuple.
 *
 * In case of an error push the error message to the Lua stack and
 * return NULL.
 */
static struct tuple *
luaT_gettuple_with_format(struct lua_State *L, int idx,
			  box_tuple_format_t *format)
{
	struct tuple *tuple;
	if (lua_istable(L, idx)) {
		/* Based on lbox_tuple_new() code. */
		struct ibuf *buf = tarantool_lua_ibuf;
		ibuf_reset(buf);
		struct mpstream stream;
		mpstream_init(&stream, buf, ibuf_reserve_cb, ibuf_alloc_cb,
		      luamp_error, L);
		luamp_encode_tuple(L, luaL_msgpack_default, &stream, idx);
		mpstream_flush(&stream);
		tuple = box_tuple_new(format, buf->buf,
				      buf->buf + ibuf_used(buf));
		if (tuple == NULL) {
			luaT_pusherror(L, diag_last_error(diag_get()));
			return NULL;
		}
		ibuf_reinit(tarantool_lua_ibuf);
		return tuple;
	}
	tuple = luaT_istuple(L, idx);
	if (tuple == NULL) {
		lua_pushfstring(L, "A tuple or a table expected, got %s",
				lua_typename(L, lua_type(L, -1)));
		return NULL;
	}
	/*
	 * Create the new tuple with the format necessary for fast
	 * comparisons.
	 */
	const char *tuple_beg = tuple_data(tuple);
	const char *tuple_end = tuple_beg + tuple->bsize;
	tuple = box_tuple_new(format, tuple_beg, tuple_end);
	if (tuple == NULL) {
		luaT_pusherror(L, diag_last_error(diag_get()));
		return NULL;
	}
	return tuple;
}

/**
 * Data comparing function to construct heap of sources.
 */
static bool
source_less(const heap_t *heap, const struct heap_node *a,
	    const struct heap_node *b)
{
	struct merger_source *left = container_of(a, struct merger_source,
						  hnode);
	struct merger_source *right = container_of(b, struct merger_source,
						   hnode);
	if (left->tuple == NULL && right->tuple == NULL)
		return false;
	if (left->tuple == NULL)
		return false;
	if (right->tuple == NULL)
		return true;
	struct merger_iterator *it = container_of(heap, struct merger_iterator,
						  heap);
	return it->order * box_tuple_compare(left->tuple, right->tuple,
					     it->key_def) < 0;
}

/**
 * Update source->tuple of specific source.
 *
 * Increases the reference counter of the tuple.
 *
 * Return 0 when successfully fetched a tuple or NULL. In case of
 * an error push an error message to the Lua stack and return 1.
 */
static int
source_fetch(struct lua_State *L, struct merger_source *source,
	     box_tuple_format_t *format)
{
	source->tuple = NULL;

	switch (source->type) {
	case SOURCE_TYPE_BUFFER: {
		if (source->buf.remaining_tuples_cnt == 0)
			return 0;
		--source->buf.remaining_tuples_cnt;
		if (ibuf_used(source->buf.buf) == 0) {
			lua_pushstring(L, "Unexpected msgpack buffer end");
			return 1;
		}
		const char *tuple_beg = source->buf.buf->rpos;
		const char *tuple_end = tuple_beg;
		/*
		 * mp_next() is faster then mp_check(), but can
		 * read bytes outside of the buffer and so can
		 * cause segmentation faults or incorrect result.
		 *
		 * We check buffer boundaries after the mp_next()
		 * call and throw an error when the boundaries are
		 * violated, but it does not save us from possible
		 * segmentation faults.
		 *
		 * It is in a user responsibility to provide valid
		 * msgpack.
		 */
		mp_next(&tuple_end);
		if (tuple_end > source->buf.buf->wpos) {
			lua_pushstring(L, "Unexpected msgpack buffer end");
			return 1;
		}
		source->buf.buf->rpos = (char *) tuple_end;
		source->tuple = box_tuple_new(format, tuple_beg, tuple_end);
		if (source->tuple == NULL) {
			luaT_pusherror(L, diag_last_error(diag_get()));
			return 1;
		}
		break;
	}
	case SOURCE_TYPE_TABLE: {
		lua_rawgeti(L, LUA_REGISTRYINDEX, source->tbl.ref);
		lua_pushinteger(L, source->tbl.next_idx);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 2);
			return 0;
		}
		source->tuple = luaT_gettuple_with_format(L, -1, format);
		if (source->tuple == NULL)
			return 1;
		++source->tbl.next_idx;
		lua_pop(L, 2);
		break;
	}
	case SOURCE_TYPE_ITERATOR: {
		int nresult = lua_iterator_next(L, source->it.it);
		if (nresult == 0)
			return 0;
		source->tuple = luaT_gettuple_with_format(L, -nresult + 1,
							  format);
		if (source->tuple == NULL)
			return 1;
		lua_pop(L, nresult);
		break;
	}
	case SOURCE_TYPE_NONE:
	default:
		unreachable();
	}
	box_tuple_ref(source->tuple);
	return 0;
}

/**
 * Extract a merger object from the Lua stack.
 */
static struct merger *
check_merger(struct lua_State *L, int idx)
{
	uint32_t cdata_type;
	struct merger **merger_ptr = luaL_checkcdata(L, idx, &cdata_type);
	if (merger_ptr == NULL || cdata_type != merger_type_id)
		return NULL;
	return *merger_ptr;
}

/**
 * Extract a merger_iterator object from the Lua stack.
 */
static struct merger_iterator *
check_merger_iterator(struct lua_State *L, int idx)
{
	uint32_t cdata_type;
	struct merger_iterator **it_ptr = luaL_checkcdata(L, idx, &cdata_type);
	if (it_ptr == NULL || cdata_type != merger_iterator_type_id)
		return NULL;
	return *it_ptr;
}

/**
 * Extract an ibuf object from the Lua stack.
 */
static struct ibuf *
check_ibuf(struct lua_State *L, int idx)
{
	if (lua_type(L, idx) != LUA_TCDATA)
		return NULL;

	uint32_t cdata_type;
	struct ibuf *ibuf_ptr = luaL_checkcdata(L, idx, &cdata_type);
	if (ibuf_ptr == NULL || cdata_type != ibuf_type_id)
		return NULL;
	return ibuf_ptr;
}

#define RPOS_P(buf) ((const char **) &(buf)->rpos)

/**
 * Skip (and check) the wrapper around tuples array (and the array
 * itself).
 *
 * Expected different kind of wrapping depending of it->decode.
 */
static int
decode_header(struct merger_iterator *it, struct ibuf *buf, size_t *len_p)
{
	int ok = 1;
	/* Decode {[IPROTO_DATA] = ...} header. */
	if (it->decode != BUFFER_TYPE_RAW)
		ok = mp_typeof(*buf->rpos) == MP_MAP &&
			mp_decode_map(RPOS_P(buf)) == 1 &&
			mp_typeof(*buf->rpos) == MP_UINT &&
			mp_decode_uint(RPOS_P(buf)) == IPROTO_DATA;
	/* Decode the array around call return values. */
	if (ok && (it->decode == BUFFER_TYPE_CALL ||
	    it->decode == BUFFER_TYPE_CHAIN))
		ok = mp_typeof(*buf->rpos) == MP_ARRAY &&
			mp_decode_array(RPOS_P(buf)) > 0;
	/* Decode the array around chained input. */
	if (ok && it->decode == BUFFER_TYPE_CHAIN)
		ok = mp_typeof(*buf->rpos) == MP_ARRAY &&
			mp_decode_array(RPOS_P(buf)) > 0;
	/* Decode the array around tuples to merge. */
	if (ok)
		ok = mp_typeof(*buf->rpos) == MP_ARRAY;
	if (ok)
		*len_p = mp_decode_array(RPOS_P(buf));
	return ok;
}

#undef RPOS_P

/**
 * Encode the wrapper around tuples array (and the array itself).
 *
 * The written msgpack depends on it->encode.
 */
static void
encode_header(struct merger_iterator *it, uint32_t result_len)
{
	struct ibuf *obuf = it->obuf;

	/* Encode {[IPROTO_DATA] = ...} header. */
	if (it->encode != BUFFER_TYPE_RAW) {
		ibuf_reserve(obuf, mp_sizeof_map(1) +
			     mp_sizeof_uint(IPROTO_DATA));
		obuf->wpos = mp_encode_map(obuf->wpos, 1);
		obuf->wpos = mp_encode_uint(obuf->wpos, IPROTO_DATA);
	}
	/* Encode the array around call return values. */
	if (it->encode == BUFFER_TYPE_CALL || it->encode == BUFFER_TYPE_CHAIN) {
		ibuf_reserve(obuf, mp_sizeof_array(1));
		obuf->wpos = mp_encode_array(obuf->wpos, 1);
	}
	/* Encode the array around chained output. */
	if (it->encode == BUFFER_TYPE_CHAIN) {
		ibuf_reserve(obuf, mp_sizeof_array(it->encode_chain_len));
		obuf->wpos = mp_encode_array(obuf->wpos, it->encode_chain_len);
	}
	/* Encode the array around resulting tuples. */
	ibuf_reserve(obuf, mp_sizeof_array(result_len));
	obuf->wpos = mp_encode_array(obuf->wpos, result_len);
}

/**
 * Push 'bad params' / 'bad param X' and the usage info to the Lua
 * stack.
 */
static int
merger_usage(struct lua_State *L, const char *param_name)
{
	static const char *usage = "merger_inst:{ipairs,pairs,select}("
				   "{source, source, ...}[, {"
				   "descending = <boolean> or <nil>, "
				   "decode = 'raw' / 'select' / 'call' / "
				   "'chain' / <nil>, "
				   "buffer = <cdata<struct ibuf>> or <nil>, "
				   "encode = 'raw' / 'select' / 'call' / "
				   "'chain' / <nil>, "
				   "encode_chain_len = <number> or <nil>}])";
	if (param_name == NULL)
		lua_pushfstring(L, "Bad params, use: %s", usage);
	else
		lua_pushfstring(L, "Bad param \"%s\", use: %s", param_name,
				usage);
	return 1;
}

/**
 * Get a tuple from a top source, update the source, update the
 * heap.
 *
 * The reference counter of the tuple is increased (in
 * source_fetch).
 *
 * Return NULL when all sources are drained.
 */
static struct tuple *
merger_next(struct lua_State *L, struct merger *merger,
	    struct merger_iterator *it)
{
	struct heap_node *hnode = merger_heap_top(&it->heap);
	if (hnode == NULL)
		return NULL;

	struct merger_source *source = container_of(hnode, struct merger_source,
						    hnode);
	struct tuple *tuple = source->tuple;
	assert(tuple != NULL);
	if (source_fetch(L, source, merger->format) != 0) {
		lua_error(L);
		unreachable();
		return NULL;
	}
	if (source->tuple == NULL)
		MERGER_HEAP_DELETE(&it->heap, hnode, source);
	else
		MERGER_HEAP_UPDATE(&it->heap, hnode, source);

	return tuple;
}

/**
 * Determine type of a merger source on the Lua stack.
 *
 * Set *buf_p to buffer when the source is valid source of buffer
 * type and buf_p is not NULL.
 */
static enum merger_source_type
parse_source_type(lua_State *L, int idx, struct ibuf **buf_p)
{
	if (lua_type(L, idx) == LUA_TCDATA) {
		struct ibuf *buf = check_ibuf(L, idx);
		if (buf == NULL)
			return SOURCE_TYPE_NONE;
		if (buf_p != NULL)
			*buf_p = buf;
		return SOURCE_TYPE_BUFFER;
	} else if (lua_istable(L, idx)) {
		lua_rawgeti(L, idx, 1);
		int iscallable = luaT_iscallable(L, idx);
		lua_pop(L, 1);
		if (iscallable)
			return SOURCE_TYPE_ITERATOR;
		return SOURCE_TYPE_TABLE;
	}

	return SOURCE_TYPE_NONE;
}

/**
 * Parse 'decode' / 'encode' options.
 */
static enum merger_buffer_type
parse_buffer_type(lua_State *L, int idx)
{
	if (lua_isnoneornil(L, idx))
		return BUFFER_TYPE_SELECT;

	if (lua_type(L, idx) != LUA_TSTRING)
		return BUFFER_TYPE_NONE;

	size_t len;
	const char *param = lua_tolstring(L, idx, &len);

	if (!strncmp(param, "raw", len))
		return BUFFER_TYPE_RAW;
	else if (!strncmp(param, "select", len))
		return BUFFER_TYPE_SELECT;
	else if (!strncmp(param, "call", len))
		return BUFFER_TYPE_CALL;
	else if (!strncmp(param, "chain", len))
		return BUFFER_TYPE_CHAIN;

	return BUFFER_TYPE_NONE;
}

/**
 * Parse optional third parameter of merger_inst:pairs() and
 * merger_inst:select() into the merger_iterator structure.
 *
 * Returns 0 on success. In case of an error it pushes an error
 * message to the Lua stack and returns 1.
 */
static int
parse_opts(struct lua_State *L, int idx, struct merger_iterator *it)
{
	/* No opts: use defaults. */
	if (lua_isnoneornil(L, idx))
		return 0;

	/* Not a table: error. */
	if (!lua_istable(L, idx))
		return merger_usage(L, NULL);

	/* Parse descending to it->order. */
	lua_pushstring(L, "descending");
	lua_gettable(L, idx);
	if (!lua_isnil(L, -1)) {
		if (lua_isboolean(L, -1))
			it->order = lua_toboolean(L, -1) ? -1 : 1;
		else
			return merger_usage(L, "descending");
	}
	lua_pop(L, 1);

	/* Parse decode to it->decode. */
	lua_pushstring(L, "decode");
	lua_gettable(L, idx);
	if (!lua_isnil(L, -1)) {
		it->decode = parse_buffer_type(L, -1);
		if (it->decode == BUFFER_TYPE_NONE)
			return merger_usage(L, "decode");
	}
	lua_pop(L, 1);

	/* Parse buffer. */
	lua_pushstring(L, "buffer");
	lua_gettable(L, idx);
	if (!lua_isnil(L, -1)) {
		if ((it->obuf = check_ibuf(L, -1)) == NULL)
			return merger_usage(L, "buffer");
	}
	lua_pop(L, 1);

	/* Parse encode to it->encode. */
	lua_pushstring(L, "encode");
	lua_gettable(L, idx);
	if (!lua_isnil(L, -1)) {
		if (it->obuf == NULL) {
			lua_pushfstring(L, "\"buffer\" option is mandatory "
					   "when \"encode\" is used");
			return 1;
		}
		it->encode = parse_buffer_type(L, -1);
		if (it->encode == BUFFER_TYPE_NONE)
			return merger_usage(L, "encode");
	}
	lua_pop(L, 1);

	/* Parse encode_chain_len. */
	lua_pushstring(L, "encode_chain_len");
	lua_gettable(L, idx);
	if (!lua_isnil(L, -1)) {
		if (it->encode != BUFFER_TYPE_CHAIN) {
			lua_pushfstring(L, "\"encode_chain_len\" is "
					   "forbidden without "
					   "{encode = 'chain'}");
			return 1;
		}
		if (lua_isnumber(L, -1))
			it->encode_chain_len =
				(uint32_t) lua_tointeger(L, -1);
		else
			return merger_usage(L, "encode_chain_len");
	}
	lua_pop(L, 1);

	/* Verify output_chain_len is provided when we
	 * going to use it for output buffer header
	 * encoding. */
	if (it->obuf != NULL && it->encode == BUFFER_TYPE_CHAIN &&
	    it->encode_chain_len == 0) {
		lua_pushfstring(L, "\"encode_chain_len\" is mandatory when "
				   "\"buffer\" and {encode = 'chain'} are "
				   "used");
		return 1;
	}

	return 0;
}

/**
 * Parse sources table: second parameter pf merger_isnt:pairs()
 * and merger_inst:select() into the merger_iterator structure.
 *
 * Note: This function should be called when options are already
 * parsed (using parse_opts()).
 *
 * Returns 0 on success. In case of an error it pushes an error
 * message to the Lua stack and returns 1.
 */
static int
parse_sources(struct lua_State *L, int idx, struct merger *merger,
	      struct merger_iterator *it)
{
	/* Allocate sources array. */
	uint32_t capacity = 8;
	const ssize_t sources_size = capacity * sizeof(struct merger_source *);
	it->sources = (struct merger_source **) malloc(sources_size);
	if (it->sources == NULL) {
		push_out_of_memory_error(L, sources_size, "it->sources");
		return 1;
	}

	/* Fetch all sources. */
	while (true) {
		lua_pushinteger(L, it->sources_count + 1);
		lua_gettable(L, idx);
		if (lua_isnil(L, -1))
			break;

		/* Shrink sources array if needed. */
		if (it->sources_count == capacity) {
			capacity *= 2;
			struct merger_source **new_sources;
			const ssize_t new_sources_size =
				capacity * sizeof(struct merger_source *);
			new_sources = (struct merger_source **) realloc(
				it->sources, new_sources_size);
			if (new_sources == NULL) {
				push_out_of_memory_error(L, new_sources_size,
							 "new_sources");
				return 1;
			}
			it->sources = new_sources;
		}

		/* Allocate the new source. */
		it->sources[it->sources_count] = (struct merger_source *)
			malloc(sizeof(struct merger_source));
		struct merger_source *current_source =
			it->sources[it->sources_count];
		if (current_source == NULL) {
			push_out_of_memory_error(L,
						 sizeof(struct merger_source),
						 "merger_source");
			return 1;
		}

		/*
		 * Set type and tuple to correctly proceed in
		 * merger_iterator_delete() in case of any further
		 * error.
		 */
		struct ibuf *buf = NULL;
		current_source->type = parse_source_type(L, -1, &buf);
		current_source->tuple = NULL;

		/*
		 * Note: We need to increment sources count right
		 * after successful malloc() of the new source
		 * (before any further error check), because
		 * merger_iterator_delete() frees that amount of
		 * sources.
		 */
		++it->sources_count;

		/* Initialize the new source. */
		switch (current_source->type) {
		case SOURCE_TYPE_BUFFER:
			if (!decode_header(it, buf,
			    &current_source->buf.remaining_tuples_cnt)) {
				lua_pushstring(L, "Invalid merge source");
				return 1;
			}
			current_source->buf.buf = buf;
			break;
		case SOURCE_TYPE_TABLE:
			/* Save a table ref and a next index. */
			lua_pushvalue(L, -1); /* Popped by luaL_ref(). */
			int tbl_ref = luaL_ref(L, LUA_REGISTRYINDEX);
			current_source->tbl.ref = tbl_ref;
			current_source->tbl.next_idx = 1;
			break;
		case SOURCE_TYPE_ITERATOR:
			/* Wrap and save iterator. */
			current_source->it.it =
				lua_iterator_new_fromtable(L, -1);
			break;
		case SOURCE_TYPE_NONE:
			lua_pushfstring(L, "Unknown source type at index %d",
					it->sources_count);
			return 1;
		default:
			unreachable();
			return 1;
		}
		if (source_fetch(L, current_source, merger->format) != 0)
			return 1;
		if (current_source->tuple != NULL)
			MERGER_HEAP_INSERT(&it->heap,
					   &current_source->hnode,
					   current_source);
	}
	lua_pop(L, it->sources_count + 1);

	return 0;
}

/**
 * Parse sources and options on Lua stack and create the new
 * merger_interator instance.
 */
static struct merger_iterator *
merger_iterator_new(struct lua_State *L)
{
	struct merger *merger;
	int ok = (lua_gettop(L) == 2 || lua_gettop(L) == 3) &&
		/* Merger. */
		(merger = check_merger(L, 1)) != NULL &&
		/* Sources. */
		lua_istable(L, 2) == 1 &&
		/* Opts. */
		(lua_isnoneornil(L, 3) == 1 || lua_istable(L, 3) == 1);
	if (!ok) {
		merger_usage(L, NULL);
		lua_error(L);
		unreachable();
		return NULL;
	}

	struct merger_iterator *it = (struct merger_iterator *)
		malloc(sizeof(struct merger_iterator));
	merger_heap_create(&it->heap);
	it->key_def = key_def_dup(merger->key_def);
	it->sources_count = 0;
	it->sources = NULL;
	it->decode = BUFFER_TYPE_NONE;
	it->order = 1;
	it->obuf = NULL;
	it->encode = BUFFER_TYPE_NONE;
	it->encode_chain_len = 0;

	if (parse_opts(L, 3, it) != 0 || parse_sources(L, 2, merger, it) != 0) {
		merger_iterator_delete(L, it);
		lua_error(L);
		unreachable();
		return NULL;
	}

	return it;
}

/**
 * Iterator gen function to traverse merger results.
 *
 * Expected a merger instance as the first parameter (state) and a
 * merger_iterator as the second parameter (param) on the Lua
 * stack.
 *
 * Push the merger_iterator (the new param) and the next tuple.
 */
static int
lbox_merger_iterator_gen(struct lua_State *L)
{
	struct merger *merger;
	struct merger_iterator *it;
	bool ok = (merger = check_merger(L, -2)) != NULL &&
		(it = check_merger_iterator(L, -1)) != NULL;
	if (!ok)
		return luaL_error(L, "Bad params, use: "
				     "lbox_merger_iterator_gen(merger, "
				     "merger_iterator)");

	struct tuple *tuple = merger_next(L, merger, it);
	if (tuple == NULL) {
		lua_pushnil(L);
		lua_pushnil(L);
		return 2;
	}

	/* Push merger_iterator, tuple. */
	*(struct merger_iterator **)
		luaL_pushcdata(L, merger_iterator_type_id) = it;
	luaT_pushtuple(L, tuple);

	box_tuple_unref(tuple);
	return 2;
}

/**
 * Iterate over merge results from Lua.
 *
 * Push three values to the Lua stack:
 *
 * 1. gen (lbox_merger_iterator_gen wrapped by fun.wrap());
 * 2. param (merger);
 * 3. state (merger_iterator).
 */
static int
lbox_merger_ipairs(struct lua_State *L)
{
	/* Create merger_iterator. */
	struct merger_iterator *it = merger_iterator_new(L);
	lua_settop(L, 1); /* Pop sources, [opts]. */
	/* Stack: merger. */

	if (it->obuf != NULL)
		return luaL_error(L, "\"buffer\" option is forbidden with "
				  "merger_inst:pairs(<...>)");

	luaL_loadstring(L, "return require('fun').wrap");
	lua_call(L, 0, 1);
	lua_insert(L, -2); /* Swap merger and wrap. */
	/* Stack: wrap, merger. */

	lua_pushcfunction(L, lbox_merger_iterator_gen);
	lua_insert(L, -2); /* Swap merger and gen. */
	/* Stack: wrap, gen, merger. */

	*(struct merger_iterator **)
		luaL_pushcdata(L, merger_iterator_type_id) = it;
	lua_pushcfunction(L, lbox_merger_iterator_gc);
	luaL_setcdatagc(L, -2);
	/* Stack: wrap, gen, merger, merger_iterator. */

	/* Call fun.wrap(gen, merger, merger_iterator). */
	lua_call(L, 3, 3);
	return 3;
}

/**
 * Write merge results into ibuf.
 */
static void
encode_result_buffer(struct lua_State *L, struct merger *merger,
		     struct merger_iterator *it)
{
	struct ibuf *obuf = it->obuf;
	uint32_t result_len = 0;
	uint32_t result_len_offset = 4;

	/*
	 * Reserve maximum size for the array around resulting
	 * tuples to set it later.
	 */
	encode_header(it, UINT32_MAX);

	/* Fetch, merge and copy tuples to the buffer. */
	struct tuple *tuple;
	while ((tuple = merger_next(L, merger, it)) != NULL) {
		uint32_t bsize = tuple->bsize;
		ibuf_reserve(obuf, bsize);
		memcpy(obuf->wpos, tuple_data(tuple), bsize);
		obuf->wpos += bsize;
		result_len_offset += bsize;
		box_tuple_unref(tuple);
		++result_len;
	}

	/* Write the real array size. */
	mp_store_u32(obuf->wpos - result_len_offset, result_len);
}

/**
 * Write merge results into the new Lua table.
 */
static int
create_result_table(struct lua_State *L, struct merger *merger,
		    struct merger_iterator *it)
{
	/* Create result table. */
	lua_newtable(L);

	uint32_t cur = 1;

	/* Fetch, merge and save tuples to the table. */
	struct tuple *tuple;
	while ((tuple = merger_next(L, merger, it)) != NULL) {
		luaT_pushtuple(L, tuple);
		lua_rawseti(L, -2, cur);
		box_tuple_unref(tuple);
		++cur;
	}

	return 1;
}

/**
 * Perform the merge.
 *
 * Write results into a buffer or a Lua table depending on options.
 *
 * Expected merger instance, sources table and options (optional)
 * on the Lua stack.
 *
 * Return the Lua table or nothing when the 'buffer' option is
 * provided.
 */
static int
lbox_merger_select(struct lua_State *L)
{
	struct merger *merger = check_merger(L, 1);
	if (merger == NULL) {
		merger_usage(L, NULL);
		lua_error(L);
	}

	struct merger_iterator *it = merger_iterator_new(L);
	lua_settop(L, 0); /* Pop merger, sources, [opts]. */

	if (it->obuf == NULL) {
		create_result_table(L, merger, it);
		merger_iterator_delete(L, it);
		return 1;
	} else {
		encode_result_buffer(L, merger, it);
		merger_iterator_delete(L, it);
		return 0;
	}
}

/**
 * Find a collation id by its name.
 *
 * To be replaced by coll_by_name() from coll_id_cache.h in
 * tarantol-2*.
 */
static uint32_t
coll_id_by_name(const char *name, size_t len)
{
	uint32_t size = mp_sizeof_array(1) + mp_sizeof_str(len);
	char begin[size];
	char *end_p = mp_encode_array(begin, 1);
	end_p = mp_encode_str(end_p, name, len);
	box_tuple_t *tuple;
	if (box_index_get(BOX_COLLATION_ID, BOX_COLLATION_NAME_INDEX,
	    begin, end_p, &tuple) != 0)
		return COLL_NONE;
	if (tuple == NULL)
		return COLL_NONE;
	uint32_t result = COLL_NONE;
	(void) tuple_field_u32(tuple, BOX_COLLATION_FIELD_ID, &result);
	return result;
}

/**
 * Create the new merger instance.
 *
 * Expected a table of key parts on the Lua stack.
 *
 * Returns the new instance.
 */
static int
lbox_merger_new(struct lua_State *L)
{
	if (lua_gettop(L) != 1 || lua_istable(L, 1) != 1)
		return luaL_error(L, "Bad params, use: merger.new({"
				  "{fieldno = fieldno, type = type"
				  "[, is_nullable = is_nullable"
				  "[, collation_id = collation_id"
				  "[, collation = collation]]]}, ...}");
	uint32_t key_parts_count = 0;
	uint32_t capacity = 8;

	const ssize_t parts_size = sizeof(struct key_part_def) * capacity;
	struct key_part_def *parts = NULL;
	parts = (struct key_part_def *) malloc(parts_size);
	if (parts == NULL)
		throw_out_of_memory_error(L, parts_size, "parts");

	while (true) {
		lua_pushinteger(L, key_parts_count + 1);
		lua_gettable(L, 1);
		if (lua_isnil(L, -1))
			break;

		/* Extend parts if necessary. */
		if (key_parts_count == capacity) {
			capacity *= 2;
			struct key_part_def *old_parts = parts;
			const ssize_t parts_size =
				sizeof(struct key_part_def) * capacity;
			parts = (struct key_part_def *) realloc(parts,
								parts_size);
			if (parts == NULL) {
				free(old_parts);
				throw_out_of_memory_error(L, parts_size,
							  "parts");
			}
		}

		/* Set parts[key_parts_count].fieldno. */
		lua_pushstring(L, "fieldno");
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			free(parts);
			return luaL_error(L, "fieldno must not be nil");
		}
		/*
		 * Transform one-based Lua fieldno to zero-based
		 * fieldno to use in key_def_new().
		 */
		parts[key_parts_count].fieldno = lua_tointeger(L, -1) - 1;
		lua_pop(L, 1);

		/* Set parts[key_parts_count].type. */
		lua_pushstring(L, "type");
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			free(parts);
			return luaL_error(L, "type must not be nil");
		}
		size_t type_len;
		const char *type_name = lua_tolstring(L, -1, &type_len);
		lua_pop(L, 1);
		parts[key_parts_count].type = field_type_by_name(type_name,
								 type_len);
		if (parts[key_parts_count].type == field_type_MAX) {
			free(parts);
			return luaL_error(L, "Unknown field type: %s",
					  type_name);
		}

		/* Set parts[key_parts_count].is_nullable. */
		lua_pushstring(L, "is_nullable");
		lua_gettable(L, -2);
		if (lua_isnil(L, -1))
			parts[key_parts_count].is_nullable = false;
		else
			parts[key_parts_count].is_nullable =
				lua_toboolean(L, -1);
		lua_pop(L, 1);

		/* Set parts[key_parts_count].coll_id using collation_id. */
		lua_pushstring(L, "collation_id");
		lua_gettable(L, -2);
		if (lua_isnil(L, -1))
			parts[key_parts_count].coll_id = COLL_NONE;
		else
			parts[key_parts_count].coll_id = lua_tointeger(L, -1);
		lua_pop(L, 1);

		/* Set parts[key_parts_count].coll_id using collation. */
		lua_pushstring(L, "collation");
		lua_gettable(L, -2);
		/* Check whether box.cfg{} was called. */
		if ((parts[key_parts_count].coll_id != COLL_NONE ||
		    !lua_isnil(L, -1)) && !box_is_configured()) {
			free(parts);
			return luaL_error(L, "Cannot use collations: "
					  "please call box.cfg{}");
		}
		if (!lua_isnil(L, -1)) {
			if (parts[key_parts_count].coll_id != COLL_NONE) {
				free(parts);
				return luaL_error(
					L, "Conflicting options: collation_id "
					"and collation");
			}
			size_t coll_name_len;
			const char *coll_name = lua_tolstring(L, -1,
							      &coll_name_len);
			parts[key_parts_count].coll_id =
				coll_id_by_name(coll_name, coll_name_len);
			if (parts[key_parts_count].coll_id == COLL_NONE) {
				free(parts);
				return luaL_error(
					L, "Unknown collation: \"%s\"",
					coll_name);
			}
		}
		lua_pop(L, 1);

		/* Check coll_id. */
		struct coll_id *coll_id =
			coll_by_id(parts[key_parts_count].coll_id);
		if (parts[key_parts_count].coll_id != COLL_NONE &&
		    coll_id == NULL) {
			uint32_t collation_id = parts[key_parts_count].coll_id;
			free(parts);
			return luaL_error(L, "Unknown collation_id: %d",
					  collation_id);
		}

		++key_parts_count;
	}

	struct merger *merger = calloc(1, sizeof(*merger));
	if (merger == NULL) {
		free(parts);
		throw_out_of_memory_error(L, sizeof(*merger), "merger");
	}
	merger->key_def = key_def_new(parts, key_parts_count);
	free(parts);
	if (merger->key_def == NULL) {
		return luaL_error(L, "Cannot create merger->key_def");
	}

	merger->format = box_tuple_format_new(&merger->key_def, 1);
	if (merger->format == NULL) {
		box_key_def_delete(merger->key_def);
		free(merger);
		return luaL_error(L, "Cannot create merger->format");
	}

	*(struct merger **) luaL_pushcdata(L, merger_type_id) = merger;

	lua_pushcfunction(L, lbox_merger_gc);
	luaL_setcdatagc(L, -2);

	return 1;
}

/**
 * Free the merger instance from a Lua code.
 */
static int
lbox_merger_gc(struct lua_State *L)
{
	struct merger *merger;
	if ((merger = check_merger(L, 1)) == NULL)
		return 0;
	box_key_def_delete(merger->key_def);
	box_tuple_format_unref(merger->format);
	free(merger);
	return 0;
}

/**
 * Free the merger iterator.
 *
 * We need to know Lua state here, because sources of table and
 * iterator types are saved as references within the Lua state.
 */
static void
merger_iterator_delete(struct lua_State *L, struct merger_iterator *it)
{
	merger_heap_destroy(&it->heap);
	box_key_def_delete(it->key_def);

	for (uint32_t i = 0; i < it->sources_count; ++i) {
		assert(it->sources != NULL);
		switch (it->sources[i]->type) {
		case SOURCE_TYPE_BUFFER:
			/* No-op. */
			break;
		case SOURCE_TYPE_TABLE:
			luaL_unref(L, LUA_REGISTRYINDEX,
				   it->sources[i]->tbl.ref);
			break;
		case SOURCE_TYPE_ITERATOR:
			lua_iterator_free(L, it->sources[i]->it.it);
			break;
		case SOURCE_TYPE_NONE:
			/*
			 * We can reach this block when
			 * parse_sources() find a bad source. Do
			 * nothing, just free the memory.
			 */
			break;
		default:
			unreachable();
		}
		if (it->sources[i]->tuple != NULL)
			box_tuple_unref(it->sources[i]->tuple);
		free(it->sources[i]);
	}

	if (it->sources != NULL) {
		assert(it->sources_count > 0);
		free(it->sources);
	}

	free(it);
}

/**
 * Free the merger iterator from a Lua code.
 */
static int
lbox_merger_iterator_gc(struct lua_State *L)
{
	struct merger_iterator *it;
	if ((it = check_merger_iterator(L, 1)) == NULL)
		return 0;
	merger_iterator_delete(L, it);
	return 0;
}

/**
 * Register the module.
 */
LUA_API int
luaopen_merger(lua_State *L)
{
	luaL_cdef(L, "struct merger;");
	luaL_cdef(L, "struct merger_iterator;");
	luaL_cdef(L, "struct ibuf;");
	merger_type_id = luaL_ctypeid(L, "struct merger&");
	merger_iterator_type_id = luaL_ctypeid(L, "struct merger_iterator&");
	ibuf_type_id = luaL_ctypeid(L, "struct ibuf");
	lua_newtable(L);
	static const struct luaL_Reg meta[] = {
		{"new", lbox_merger_new},
		{NULL, NULL}
	};
	luaL_register_module(L, "merger", meta);

	/* Export C functions to Lua. */
	lua_newtable(L); /* merger.internal */
	lua_pushcfunction(L, lbox_merger_select);
	lua_setfield(L, -2, "select");
	lua_pushcfunction(L, lbox_merger_ipairs);
	lua_setfield(L, -2, "ipairs");
	lua_setfield(L, -2, "internal");

	return 1;
}
