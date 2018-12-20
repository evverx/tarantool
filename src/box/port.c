/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
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
#include "port.h"
#include "tuple.h"
#include "tuple_convert.h"
#include <small/obuf.h>
#include <small/slab_cache.h>
#include <small/mempool.h>
#include <fiber.h>
#include "errinj.h"

#include "iproto_constants.h"
#include "sql/sqliteInt.h"
#include "execute.h"

static struct mempool port_tuple_entry_pool;

int
port_tuple_add(struct port *base, struct tuple *tuple)
{
	struct port_tuple *port = port_tuple(base);
	struct port_tuple_entry *e;
	if (port->size == 0) {
		tuple_ref(tuple);
		e = &port->first_entry;
		port->first = port->last = e;
	} else {
		e = mempool_alloc(&port_tuple_entry_pool);
		if (e == NULL) {
			diag_set(OutOfMemory, sizeof(*e), "mempool_alloc", "e");
			return -1;
		}
		tuple_ref(tuple);
		port->last->next = e;
		port->last = e;
	}
	e->tuple = tuple;
	e->next = NULL;
	++port->size;
	return 0;
}

void
port_tuple_create(struct port *base)
{
	struct port_tuple *port = (struct port_tuple *)base;
	port->vtab = &port_tuple_vtab;
	port->size = 0;
	port->first = NULL;
	port->last = NULL;
}

static void
port_tuple_destroy(struct port *base)
{
	struct port_tuple *port = port_tuple(base);
	struct port_tuple_entry *e = port->first;
	if (e == NULL)
		return;
	tuple_unref(e->tuple);
	e = e->next;
	while (e != NULL) {
		struct port_tuple_entry *cur = e;
		e = e->next;
		tuple_unref(cur->tuple);
		mempool_free(&port_tuple_entry_pool, cur);
	}
}

static int
port_tuple_dump_msgpack_16(struct port *base, struct obuf *out)
{
	struct port_tuple *port = port_tuple(base);
	struct port_tuple_entry *pe;
	for (pe = port->first; pe != NULL; pe = pe->next) {
		if (tuple_to_obuf(pe->tuple, out) != 0)
			return -1;
		ERROR_INJECT(ERRINJ_PORT_DUMP, {
			diag_set(OutOfMemory, tuple_size(pe->tuple), "obuf_dup",
				 "data");
			return -1;
		});
	}
	return port->size;
}

static int
port_tuple_dump_msgpack(struct port *base, struct obuf *out)
{
	struct port_tuple *port = port_tuple(base);
	char *size_buf = obuf_alloc(out, mp_sizeof_array(port->size));
	if (size_buf == NULL)
		return -1;
	mp_encode_array(size_buf, port->size);
	if (port_tuple_dump_msgpack_16(base, out) < 0)
		return -1;
	return 1;
}

extern void
port_tuple_dump_lua(struct port *base, struct lua_State *L);

void
port_init(void)
{
	mempool_create(&port_tuple_entry_pool, &cord()->slabc,
		       sizeof(struct port_tuple_entry));
}

void
port_free(void)
{
	mempool_destroy(&port_tuple_entry_pool);
}

const struct port_vtab port_tuple_vtab = {
	.dump_msgpack = port_tuple_dump_msgpack,
	.dump_msgpack_16 = port_tuple_dump_msgpack_16,
	.dump_lua = port_tuple_dump_lua,
	.dump_plain = NULL,
	.destroy = port_tuple_destroy,
};

/**
 * Serialize a description of the prepared statement.
 * @param stmt Prepared statement.
 * @param out Out buffer.
 * @param column_count Statement's column count.
 *
 * @retval  0 Success.
 * @retval -1 Client or memory error.
 */
static inline int
sql_get_description(struct sqlite3_stmt *stmt, struct obuf *out,
		    int column_count)
{
	assert(column_count > 0);
	int size = mp_sizeof_uint(IPROTO_METADATA) +
		   mp_sizeof_array(column_count);
	char *pos = (char *) obuf_alloc(out, size);
	if (pos == NULL) {
		diag_set(OutOfMemory, size, "obuf_alloc", "pos");
		return -1;
	}
	pos = mp_encode_uint(pos, IPROTO_METADATA);
	pos = mp_encode_array(pos, column_count);
	for (int i = 0; i < column_count; ++i) {
		size_t size = mp_sizeof_map(2) +
			      mp_sizeof_uint(IPROTO_FIELD_NAME) +
			      mp_sizeof_uint(IPROTO_FIELD_TYPE);
		const char *name = sqlite3_column_name(stmt, i);
		const char *type = sqlite3_column_datatype(stmt, i);
		/*
		 * Can not fail, since all column names are
		 * preallocated during prepare phase and the
		 * column_name simply returns them.
		 */
		assert(name != NULL);
		size += mp_sizeof_str(strlen(name));
		size += mp_sizeof_str(strlen(type));
		char *pos = (char *) obuf_alloc(out, size);
		if (pos == NULL) {
			diag_set(OutOfMemory, size, "obuf_alloc", "pos");
			return -1;
		}
		pos = mp_encode_map(pos, 2);
		pos = mp_encode_uint(pos, IPROTO_FIELD_NAME);
		pos = mp_encode_str(pos, name, strlen(name));
		pos = mp_encode_uint(pos, IPROTO_FIELD_TYPE);
		pos = mp_encode_str(pos, type, strlen(type));
	}
	return 0;
}

int
sql_response_dump(struct port *port, struct obuf *out)
{
	sqlite3 *db = sql_get();
	struct sqlite3_stmt *stmt = ((struct port_sql *)port)->stmt;
	struct port_tuple *port_tuple = (struct port_tuple *) port;
	int rc = 0, column_count = sqlite3_column_count(stmt);
	if (column_count > 0) {
		int keys = 2;
		int size = mp_sizeof_map(keys);
		char *pos = (char *) obuf_alloc(out, size);
		if (pos == NULL) {
			diag_set(OutOfMemory, size, "obuf_alloc", "pos");
			goto err;
		}
		pos = mp_encode_map(pos, keys);
		if (sql_get_description(stmt, out, column_count) != 0) {
err:
			rc = -1;
			goto finish;
		}
		size = mp_sizeof_uint(IPROTO_DATA) +
		       mp_sizeof_array(port_tuple->size);
		pos = (char *) obuf_alloc(out, size);
		if (pos == NULL) {
			diag_set(OutOfMemory, size, "obuf_alloc", "pos");
			goto err;
		}
		pos = mp_encode_uint(pos, IPROTO_DATA);
		pos = mp_encode_array(pos, port_tuple->size);
		/*
		 * Just like SELECT, SQL uses output format compatible
		 * with Tarantool 1.6
		 */
		if (port_dump_msgpack_16(port, out) < 0) {
			/* Failed port dump destroyes the port. */
			goto err;
		}
	} else {
		int keys = 1;
		assert(port_tuple->size == 0);
		struct stailq *autoinc_id_list =
			vdbe_autoinc_id_list((struct Vdbe *)stmt);
		uint32_t map_size = stailq_empty(autoinc_id_list) ? 1 : 2;
		int size = mp_sizeof_map(keys) +
			   mp_sizeof_uint(IPROTO_SQL_INFO) +
			   mp_sizeof_map(map_size);
		char *pos = (char *) obuf_alloc(out, size);
		if (pos == NULL) {
			diag_set(OutOfMemory, size, "obuf_alloc", "pos");
			goto err;
		}
		pos = mp_encode_map(pos, keys);
		pos = mp_encode_uint(pos, IPROTO_SQL_INFO);
		pos = mp_encode_map(pos, map_size);
		uint64_t id_count = 0;
		int changes = db->nChange;
		size = mp_sizeof_uint(SQL_INFO_ROW_COUNT) +
		       mp_sizeof_uint(changes);
		if (!stailq_empty(autoinc_id_list)) {
			struct autoinc_id_entry *id_entry;
			stailq_foreach_entry(id_entry, autoinc_id_list, link) {
				size += id_entry->id >= 0 ?
					mp_sizeof_uint(id_entry->id) :
					mp_sizeof_int(id_entry->id);
				id_count++;
			}
			size += mp_sizeof_uint(SQL_INFO_AUTOINCREMENT_IDS) +
				mp_sizeof_array(id_count);
		}
		char *buf = obuf_alloc(out, size);
		if (buf == NULL) {
			diag_set(OutOfMemory, size, "obuf_alloc", "buf");
			goto err;
		}
		buf = mp_encode_uint(buf, SQL_INFO_ROW_COUNT);
		buf = mp_encode_uint(buf, changes);
		if (!stailq_empty(autoinc_id_list)) {
			buf = mp_encode_uint(buf, SQL_INFO_AUTOINCREMENT_IDS);
			buf = mp_encode_array(buf, id_count);
			struct autoinc_id_entry *id_entry;
			stailq_foreach_entry(id_entry, autoinc_id_list, link) {
				buf = id_entry->id >= 0 ?
				      mp_encode_uint(buf, id_entry->id) :
				      mp_encode_int(buf, id_entry->id);
			}
		}
	}
finish:
	port_destroy(port);
	sqlite3_finalize(stmt);
	return rc;
}
