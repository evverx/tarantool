/*
 * Copyright 2010-2017, Tarantool AUTHORS, please see AUTHORS file.
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
#include "execute.h"

#include "iproto_constants.h"
#include "sql/sqliteInt.h"
#include "sql/sqliteLimit.h"
#include "errcode.h"
#include "small/region.h"
#include "diag.h"
#include "sql.h"
#include "xrow.h"
#include "schema.h"
#include "port.h"
#include "tuple.h"
#include "sql/vdbe.h"
#include "vstream.h"
#include "lua/utils.h"
#include "lua/msgpack.h"

const char *sql_type_strs[] = {
	NULL,
	"INTEGER",
	"FLOAT",
	"TEXT",
	"BLOB",
	"NULL",
};

const char *sql_info_key_strs[] = {
	"row count",
};

/**
 * Name and value of an SQL prepared statement parameter.
 * @todo: merge with sqlite3_value.
 */
struct sql_bind {
	/** Bind name. NULL for ordinal binds. */
	const char *name;
	/** Length of the @name. */
	uint32_t name_len;
	/** Ordinal position of the bind, for ordinal binds. */
	uint32_t pos;

	/** Byte length of the value. */
	uint32_t bytes;
	/** SQL type of the value. */
	uint8_t type;
	/** Bind value. */
	union {
		double d;
		int64_t i64;
		/** For string or blob. */
		const char *s;
	};
};

/**
 * Return a string name of a parameter marker.
 * @param Bind to get name.
 * @retval Zero terminated name.
 */
static inline const char *
sql_bind_name(const struct sql_bind *bind)
{
	if (bind->name)
		return tt_sprintf("'%.*s'", bind->name_len, bind->name);
	else
		return tt_sprintf("%d", (int) bind->pos);
}

/**
 * Decode a single bind column from the binary protocol packet.
 * @param[out] bind Bind to decode to.
 * @param i Ordinal bind number.
 * @param packet MessagePack encoded parameter value. Either
 *        scalar or map: {string_name: scalar_value}.
 *
 * @retval  0 Success.
 * @retval -1 Memory or client error.
 */
static inline int
sql_bind_decode(struct sql_bind *bind, int i, const char **packet)
{
	bind->pos = i + 1;
	if (mp_typeof(**packet) == MP_MAP) {
		uint32_t len = mp_decode_map(packet);
		/*
		 * A named parameter is an MP_MAP with
		 * one key - {'name': value}.
		 * Report parse error otherwise.
		 */
		if (len != 1 || mp_typeof(**packet) != MP_STR) {
			diag_set(ClientError, ER_INVALID_MSGPACK,
				 "SQL bind parameter");
			return -1;
		}
		bind->name = mp_decode_str(packet, &bind->name_len);
	} else {
		bind->name = NULL;
		bind->name_len = 0;
	}
	switch (mp_typeof(**packet)) {
	case MP_UINT: {
		uint64_t n = mp_decode_uint(packet);
		if (n > INT64_MAX) {
			diag_set(ClientError, ER_SQL_BIND_VALUE,
				 sql_bind_name(bind), "INTEGER");
			return -1;
		}
		bind->i64 = (int64_t) n;
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	}
	case MP_INT:
		bind->i64 = mp_decode_int(packet);
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	case MP_STR:
		bind->s = mp_decode_str(packet, &bind->bytes);
		bind->type = SQLITE_TEXT;
		break;
	case MP_DOUBLE:
		bind->d = mp_decode_double(packet);
		bind->type = SQLITE_FLOAT;
		bind->bytes = sizeof(bind->d);
		break;
	case MP_FLOAT:
		bind->d = mp_decode_float(packet);
		bind->type = SQLITE_FLOAT;
		bind->bytes = sizeof(bind->d);
		break;
	case MP_NIL:
		mp_decode_nil(packet);
		bind->type = SQLITE_NULL;
		bind->bytes = 1;
		break;
	case MP_BOOL:
		/* SQLite doesn't support boolean. Use int instead. */
		bind->i64 = mp_decode_bool(packet) ? 1 : 0;
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	case MP_BIN:
		bind->s = mp_decode_bin(packet, &bind->bytes);
		bind->type = SQLITE_BLOB;
		break;
	case MP_EXT:
		bind->s = *packet;
		mp_next(packet);
		bind->bytes = *packet - bind->s;
		bind->type = SQLITE_BLOB;
		break;
	case MP_ARRAY:
		diag_set(ClientError, ER_SQL_BIND_TYPE, "ARRAY",
			 sql_bind_name(bind));
		return -1;
	case MP_MAP:
		diag_set(ClientError, ER_SQL_BIND_TYPE, "MAP",
			 sql_bind_name(bind));
		return -1;
	default:
		unreachable();
	}
	return 0;
}

/**
 * Parse MessagePack array of SQL parameters and store a result
 * into the @request->bind, bind_count.
 * @param request Request to save decoded parameters.
 * @param data MessagePack array of parameters. Each parameter
 *        either must have scalar type, or must be a map with the
 *        following format: {name: value}. Name - string name of
 *        the named parameter, value - scalar value of the
 *        parameter. Named and positioned parameters can be mixed.
 *        For more details
 *        @sa https://www.sqlite.org/lang_expr.html#varparam.
 * @param region Allocator.
 *
 * @retval  0 Success.
 * @retval -1 Client or memory error.
 */
static inline int
sql_bind_list_decode(struct sql_request *request, const char *data,
		     struct region *region)
{
	assert(request != NULL);
	assert(data != NULL);
	if (mp_typeof(*data) != MP_ARRAY) {
		diag_set(ClientError, ER_INVALID_MSGPACK, "SQL parameter list");
		return -1;
	}
	uint32_t bind_count = mp_decode_array(&data);
	if (bind_count == 0)
		return 0;
	if (bind_count > SQL_BIND_PARAMETER_MAX) {
		diag_set(ClientError, ER_SQL_BIND_PARAMETER_MAX,
			 (int) bind_count);
		return -1;
	}
	uint32_t used = region_used(region);
	size_t size = sizeof(struct sql_bind) * bind_count;
	struct sql_bind *bind = (struct sql_bind *) region_alloc(region, size);
	if (bind == NULL) {
		diag_set(OutOfMemory, size, "region_alloc", "struct sql_bind");
		return -1;
	}
	for (uint32_t i = 0; i < bind_count; ++i) {
		if (sql_bind_decode(&bind[i], i, &data) != 0) {
			region_truncate(region, used);
			return -1;
		}
	}
	request->bind_count = bind_count;
	request->bind = bind;
	return 0;
}

int
xrow_decode_sql(const struct xrow_header *row, struct sql_request *request,
		struct region *region)
{
	if (row->bodycnt == 0) {
		diag_set(ClientError, ER_INVALID_MSGPACK, "missing request body");
		return 1;
	}
	assert(row->bodycnt == 1);
	const char *data = (const char *) row->body[0].iov_base;
	const char *end = data + row->body[0].iov_len;
	assert((end - data) > 0);

	if (mp_typeof(*data) != MP_MAP || mp_check_map(data, end) > 0) {
error:
		diag_set(ClientError, ER_INVALID_MSGPACK, "packet body");
		return -1;
	}

	uint32_t map_size = mp_decode_map(&data);
	request->sql_text = NULL;
	request->bind = NULL;
	request->bind_count = 0;
	request->sync = row->sync;
	for (uint32_t i = 0; i < map_size; ++i) {
		uint8_t key = *data;
		if (key != IPROTO_SQL_BIND && key != IPROTO_SQL_TEXT) {
			mp_check(&data, end);   /* skip the key */
			mp_check(&data, end);   /* skip the value */
			continue;
		}
		const char *value = ++data;     /* skip the key */
		if (mp_check(&data, end) != 0)  /* check the value */
			goto error;
		if (key == IPROTO_SQL_BIND) {
			if (sql_bind_list_decode(request, value, region) != 0)
				return -1;
		} else {
			request->sql_text =
				mp_decode_str(&value, &request->sql_text_len);
		}
	}
	if (request->sql_text == NULL) {
		diag_set(ClientError, ER_MISSING_REQUEST_FIELD,
			 iproto_key_name(IPROTO_SQL_TEXT));
		return -1;
	}
	if (data != end)
		goto error;
	return 0;
}

/**
 * Decode a single bind column from Lua stack.
 *
 * @param L Lua stack.
 * @param[out] bind Bind to decode to.
 * @param idx Position of table with bind columns on Lua stack.
 * @param i Ordinal bind number.
 *
 * @retval  0 Success.
 * @retval -1 Memory or client error.
 */
static inline int
lua_sql_bind_decode(struct lua_State *L, struct sql_bind *bind, int idx, int i)
{
	struct luaL_field field;
	char *buf;
	lua_rawgeti(L, idx, i + 1);
	luaL_tofield(L, luaL_msgpack_default, -1, &field);
	bind->pos = i + 1;
	if (field.type == MP_MAP) {
		/*
		 * A named parameter is an MP_MAP with
		 * one key - {'name': value}.
		 * Report parse error otherwise.
		 */
		if (field.size != 1) {
			diag_set(ClientError, ER_ILLEGAL_PARAMS, "SQL bind "\
				 "parameter should be {'name': value}");
			return -1;
		}
		/*
		 * Get key and value of the only map element to
		 * lua stack.
		 */
		lua_pushnil(L);
		lua_next(L, lua_gettop(L) - 1);
		/* At first we should deal with the value. */
		luaL_tofield(L, luaL_msgpack_default, -1, &field);
		lua_pop(L, 1);
		/* Now key is on the top of Lua stack. */
		size_t name_len = 0;
		bind->name = luaL_checklstring(L, -1, &name_len);
		if (bind->name == NULL) {
			diag_set(ClientError, ER_ILLEGAL_PARAMS, "SQL bind "\
				 "parameter should be {'name': value}");
			return -1;
		}
		/*
		 * Name should be saved in allocated memory as it
		 * will be poped from Lua stack.
		 */
		buf = region_alloc(&fiber()->gc, name_len + 1);
		if (buf == NULL) {
			diag_set(OutOfMemory, name_len + 1, "region_alloc",
				 "buf");
			return -1;
		}
		memcpy(buf, bind->name, name_len + 1);
		bind->name = buf;
		bind->name_len = name_len;
		lua_pop(L, 1);
	} else {
		bind->name = NULL;
		bind->name_len = 0;
	}
	switch (field.type) {
	case MP_UINT: {
		bind->i64 = field.ival;
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	}
	case MP_INT:
		bind->i64 = field.ival;
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	case MP_STR:
		/*
		 * Data should be saved in allocated memory as it
		 * will be poped from Lua stack.
		 */
		buf = region_alloc(&fiber()->gc, field.sval.len + 1);
		if (buf == NULL) {
			diag_set(OutOfMemory, field.sval.len + 1,
				 "region_alloc", "buf");
			return -1;
		}
		memcpy(buf, field.sval.data, field.sval.len + 1);
		bind->s = buf;
		bind->type = SQLITE_TEXT;
		bind->bytes = field.sval.len;
		break;
	case MP_DOUBLE:
		bind->d = field.dval;
		bind->type = SQLITE_FLOAT;
		bind->bytes = sizeof(bind->d);
		break;
	case MP_FLOAT:
		bind->d = field.dval;
		bind->type = SQLITE_FLOAT;
		bind->bytes = sizeof(bind->d);
		break;
	case MP_NIL:
		bind->type = SQLITE_NULL;
		bind->bytes = 1;
		break;
	case MP_BOOL:
		/* SQLite doesn't support boolean. Use int instead. */
		bind->i64 = field.bval ? 1 : 0;
		bind->type = SQLITE_INTEGER;
		bind->bytes = sizeof(bind->i64);
		break;
	case MP_BIN:
		bind->s = mp_decode_bin(&field.sval.data, &bind->bytes);
		bind->type = SQLITE_BLOB;
		break;
	case MP_EXT:
		/*
		 * Data should be saved in allocated memory as it
		 * will be poped from Lua stack.
		 */
		buf = region_alloc(&fiber()->gc, sizeof(field));
		if (buf == NULL) {
			diag_set(OutOfMemory, sizeof(field), "region_alloc",
				 "buf");
			return -1;
		}
		memcpy(buf, &field, sizeof(field));
		bind->s = buf;
		bind->bytes = sizeof(field);
		bind->type = SQLITE_BLOB;
		break;
	case MP_ARRAY:
		diag_set(ClientError, ER_SQL_BIND_TYPE, "ARRAY",
			 sql_bind_name(bind));
		return -1;
	case MP_MAP:
		diag_set(ClientError, ER_SQL_BIND_TYPE, "MAP",
			 sql_bind_name(bind));
		return -1;
	default:
		unreachable();
	}
	lua_pop(L, 1);
	return 0;
}

int
lua_sql_bind_list_decode(struct lua_State *L, struct sql_request *request,
			 int idx)
{
	assert(request != NULL);
	if (! lua_istable(L, idx)) {
		diag_set(ClientError, ER_INVALID_MSGPACK, "SQL parameter list");
		return -1;
	}
	uint32_t bind_count = lua_objlen(L, idx);
	if (bind_count == 0)
		return 0;
	if (bind_count > SQL_BIND_PARAMETER_MAX) {
		diag_set(ClientError, ER_SQL_BIND_PARAMETER_MAX,
			 (int) bind_count);
		return -1;
	}
	struct region *region = &fiber()->gc;
	uint32_t used = region_used(region);
	size_t size = sizeof(struct sql_bind) * bind_count;
	/*
	 * Memory allocated here will be freed in
	 * sqlite3_finalize() or in txn_commit()/txn_rollback() if
	 * there is an active transaction.
	 */
	struct sql_bind *bind = (struct sql_bind *) region_alloc(region, size);
	if (bind == NULL) {
		diag_set(OutOfMemory, size, "region_alloc", "bind");
		return -1;
	}
	for (uint32_t i = 0; i < bind_count; ++i) {
		if (lua_sql_bind_decode(L, &bind[i], idx, i) != 0) {
			region_truncate(region, used);
			return -1;
		}
	}
	request->bind_count = bind_count;
	request->bind = bind;
	return 0;
}

/**
 * Serialize a single column of a result set row.
 * @param stmt Prepared and started statement. At least one
 *        sqlite3_step must be called.
 * @param i Column number.
 * @param region Allocator for column value.
 *
 * @retval  0 Success.
 * @retval -1 Out of memory when resizing the output buffer.
 */
static inline int
sql_column_to_messagepack(struct sqlite3_stmt *stmt, int i,
			  struct region *region)
{
	size_t size;
	int type = sqlite3_column_type(stmt, i);
	switch (type) {
	case SQLITE_INTEGER: {
		int64_t n = sqlite3_column_int64(stmt, i);
		if (n >= 0)
			size = mp_sizeof_uint(n);
		else
			size = mp_sizeof_int(n);
		char *pos = (char *) region_alloc(region, size);
		if (pos == NULL)
			goto oom;
		if (n >= 0)
			mp_encode_uint(pos, n);
		else
			mp_encode_int(pos, n);
		break;
	}
	case SQLITE_FLOAT: {
		double d = sqlite3_column_double(stmt, i);
		size = mp_sizeof_double(d);
		char *pos = (char *) region_alloc(region, size);
		if (pos == NULL)
			goto oom;
		mp_encode_double(pos, d);
		break;
	}
	case SQLITE_TEXT: {
		uint32_t len = sqlite3_column_bytes(stmt, i);
		size = mp_sizeof_str(len);
		char *pos = (char *) region_alloc(region, size);
		if (pos == NULL)
			goto oom;
		const char *s;
		s = (const char *)sqlite3_column_text(stmt, i);
		mp_encode_str(pos, s, len);
		break;
	}
	case SQLITE_BLOB: {
		uint32_t len = sqlite3_column_bytes(stmt, i);
		const char *s =
			(const char *)sqlite3_column_blob(stmt, i);
		if (sql_column_subtype(stmt, i) == SQL_SUBTYPE_MSGPACK) {
			size = len;
			char *pos = (char *)region_alloc(region, size);
			if (pos == NULL)
				goto oom;
			memcpy(pos, s, len);
		} else {
			size = mp_sizeof_bin(len);
			char *pos = (char *)region_alloc(region, size);
			if (pos == NULL)
				goto oom;
			mp_encode_bin(pos, s, len);
		}
		break;
	}
	case SQLITE_NULL: {
		size = mp_sizeof_nil();
		char *pos = (char *) region_alloc(region, size);
		if (pos == NULL)
			goto oom;
		mp_encode_nil(pos);
		break;
	}
	default:
		unreachable();
	}
	return 0;
oom:
	diag_set(OutOfMemory, size, "region_alloc", "SQL value");
	return -1;
}

/**
 * Convert sqlite3 row into a tuple and append to a port.
 * @param stmt Started prepared statement. At least one
 *        sqlite3_step must be done.
 * @param column_count Statement's column count.
 * @param region Runtime allocator for temporary objects.
 * @param port Port to store tuples.
 *
 * @retval  0 Success.
 * @retval -1 Memory error.
 */
static inline int
sql_row_to_port(struct sqlite3_stmt *stmt, int column_count,
		struct region *region, struct port *port)
{
	assert(column_count > 0);
	size_t size = mp_sizeof_array(column_count);
	size_t svp = region_used(region);
	char *pos = (char *) region_alloc(region, size);
	if (pos == NULL) {
		diag_set(OutOfMemory, size, "region_alloc", "SQL row");
		return -1;
	}
	mp_encode_array(pos, column_count);

	for (int i = 0; i < column_count; ++i) {
		if (sql_column_to_messagepack(stmt, i, region) != 0)
			goto error;
	}
	size = region_used(region) - svp;
	pos = (char *) region_join(region, size);
	if (pos == NULL) {
		diag_set(OutOfMemory, size, "region_join", "pos");
		goto error;
	}
	struct tuple *tuple =
		tuple_new(box_tuple_format_default(), pos, pos + size);
	if (tuple == NULL)
		goto error;
	region_truncate(region, svp);
	return port_tuple_add(port, tuple);

error:
	region_truncate(region, svp);
	return -1;
}

/**
 * Bind SQL parameter value to its position.
 * @param stmt Prepared statement.
 * @param p Parameter value.
 * @param pos Ordinal bind position.
 *
 * @retval  0 Success.
 * @retval -1 SQL error.
 */
static inline int
sql_bind_column(struct sqlite3_stmt *stmt, const struct sql_bind *p,
		uint32_t pos)
{
	int rc;
	if (p->name != NULL) {
		pos = sqlite3_bind_parameter_lindex(stmt, p->name, p->name_len);
		if (pos == 0) {
			diag_set(ClientError, ER_SQL_BIND_NOT_FOUND,
				 sql_bind_name(p));
			return -1;
		}
	}
	switch (p->type) {
	case SQLITE_INTEGER:
		rc = sqlite3_bind_int64(stmt, pos, p->i64);
		break;
	case SQLITE_FLOAT:
		rc = sqlite3_bind_double(stmt, pos, p->d);
		break;
	case SQLITE_TEXT:
		/*
		 * Parameters are allocated within message pack,
		 * received from the iproto thread. IProto thread
		 * now is waiting for the response and it will not
		 * free the packet until sqlite3_finalize. So
		 * there is no need to copy the packet and we can
		 * use SQLITE_STATIC.
		 */
		rc = sqlite3_bind_text64(stmt, pos, p->s, p->bytes,
					 SQLITE_STATIC);
		break;
	case SQLITE_NULL:
		rc = sqlite3_bind_null(stmt, pos);
		break;
	case SQLITE_BLOB:
		rc = sqlite3_bind_blob64(stmt, pos, (const void *) p->s,
					 p->bytes, SQLITE_STATIC);
		break;
	default:
		unreachable();
	}
	if (rc == SQLITE_OK)
		return 0;

	switch (rc) {
	case SQLITE_NOMEM:
		diag_set(OutOfMemory, p->bytes, "vdbe", "bind value");
		break;
	case SQLITE_TOOBIG:
	default:
		diag_set(ClientError, ER_SQL_BIND_VALUE, sql_bind_name(p),
			 sql_type_strs[p->type]);
		break;
	}
	return -1;
}

/**
 * Bind parameter values to the prepared statement.
 * @param request Parsed SQL request.
 * @param stmt Prepared statement.
 *
 * @retval  0 Success.
 * @retval -1 Client or memory error.
 */
static inline int
sql_bind(const struct sql_request *request, struct sqlite3_stmt *stmt)
{
	assert(stmt != NULL);
	uint32_t pos = 1;
	for (uint32_t i = 0; i < request->bind_count; pos = ++i + 1) {
		if (sql_bind_column(stmt, &request->bind[i], pos) != 0)
			return -1;
	}
	return 0;
}

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
sql_get_description(struct sqlite3_stmt *stmt, struct vstream *stream,
		    int column_count)
{
	assert(column_count > 0);
	vstream_encode_enum(stream, IPROTO_METADATA, "metadata");
	vstream_encode_array(stream, column_count);
	for (int i = 0; i < column_count; ++i) {
		const char *name = sqlite3_column_name(stmt, i);
		const char *type = sqlite3_column_datatype(stmt, i);
		/*
		 * Can not fail, since all column names are
		 * preallocated during prepare phase and the
		 * column_name simply returns them.
		 */
		assert(name != NULL);
		if (type == NULL)
			type = "UNKNOWN";
		vstream_encode_map(stream, 2);

		vstream_encode_enum(stream, IPROTO_FIELD_NAME, "name");
		vstream_encode_str(stream, name);
		vstream_encode_map_commit(stream);

		vstream_encode_enum(stream, IPROTO_FIELD_TYPE, "type");
		vstream_encode_str(stream, type);
		vstream_encode_map_commit(stream);

		vstream_encode_array_commit(stream, i);
	}
	vstream_encode_map_commit(stream);
	return 0;
}

static inline int
sql_execute(sqlite3 *db, struct sqlite3_stmt *stmt, struct port *port,
	    struct region *region, int error_id)
{
	int rc, column_count = sqlite3_column_count(stmt);
	if (column_count > 0) {
		/* Either ROW or DONE or ERROR. */
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			if (sql_row_to_port(stmt, column_count, region,
					    port) != 0)
				return -1;
		}
		assert(rc == SQLITE_DONE || rc != SQLITE_OK);
	} else {
		/* No rows. Either DONE or ERROR. */
		rc = sqlite3_step(stmt);
		assert(rc != SQLITE_ROW && rc != SQLITE_OK);
	}
	if (rc != SQLITE_DONE) {
		diag_set(ClientError, error_id, sqlite3_errmsg(db));
		return -1;
	}
	return 0;
}

int
sql_prepare_and_execute(const struct sql_request *request,
			struct sql_response *response, struct region *region,
			int error_id)
{
	const char *sql = request->sql_text;
	uint32_t len = request->sql_text_len;
	struct sqlite3_stmt *stmt;
	sqlite3 *db = sql_get();
	if (db == NULL) {
		diag_set(ClientError, ER_LOADING);
		return -1;
	}
	if (sqlite3_prepare_v2(db, sql, len, &stmt, NULL) != SQLITE_OK) {
		diag_set(ClientError, error_id, sqlite3_errmsg(db));
		return -1;
	}
	assert(stmt != NULL);
	port_tuple_create(&response->port);
	response->prep_stmt = stmt;
	response->sync = request->sync;
	if (sql_bind(request, stmt) == 0 &&
	    sql_execute(db, stmt, &response->port, region, error_id) == 0)
		return 0;
	port_destroy(&response->port);
	sqlite3_finalize(stmt);
	return -1;
}

int
sql_response_dump(struct sql_response *response, int *keys,
		  struct vstream *stream)
{
	sqlite3 *db = sql_get();
	struct sqlite3_stmt *stmt = (struct sqlite3_stmt *) response->prep_stmt;
	int rc = 0, column_count = sqlite3_column_count(stmt);
	if (column_count > 0) {
		if (sql_get_description(stmt, stream, column_count) != 0) {
err:
			rc = -1;
			goto finish;
		}
		*keys = 2;
		vstream_encode_enum(stream, IPROTO_DATA, "rows");
		if (vstream_encode_port(stream, &response->port) < 0) {
			/* Failed port dump destroyes the port. */
			goto err;
		}
		vstream_encode_map_commit(stream);
	} else {
		*keys = 1;
		struct stailq *autoinc_id_list =
			vdbe_autoinc_id_list((struct Vdbe *)stmt);
		uint32_t map_size = stailq_empty(autoinc_id_list) ? 1 : 2;
		uint64_t id_count = 0;
		if (!stailq_empty(autoinc_id_list)) {
			struct autoinc_id_entry *id_entry;
			stailq_foreach_entry(id_entry, autoinc_id_list, link)
				id_count++;
		}
		if (!response->is_info_flattened) {
			vstream_encode_enum(stream, IPROTO_SQL_INFO, "info");
			vstream_encode_map(stream, map_size);
		}
		vstream_encode_enum(stream, SQL_INFO_ROW_COUNT, "rowcount");
		vstream_encode_uint(stream, db->nChange);
		vstream_encode_map_commit(stream);
		if (!stailq_empty(autoinc_id_list)) {
			vstream_encode_enum(stream, SQL_INFO_AUTOINCREMENT_IDS,
					    "autoincrement_ids");
			vstream_encode_array(stream, id_count);
			struct autoinc_id_entry *id_entry;
			int i = 0;
			stailq_foreach_entry(id_entry, autoinc_id_list, link) {
				int64_t value = id_entry->id;
				if (id_entry->id >= 0)
					vstream_encode_uint(stream, value);
				else
					vstream_encode_int(stream, value);
				vstream_encode_array_commit(stream, i++);
			}
			vstream_encode_map_commit(stream);
		}
		if (!response->is_info_flattened)
			vstream_encode_map_commit(stream);
	}
finish:
	port_destroy(&response->port);
	sqlite3_finalize(stmt);
	return rc;
}
