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
#include "luastream.h"
#include "lua/utils.h"
#include "vstream.h"
#include "port.h"

void
luastream_init(struct luastream *stream, struct lua_State *L)
{
	stream->L = L;
}

static void
luastream_encode_array(struct luastream *stream, uint32_t size)
{
	lua_createtable(stream->L, size, 0);
}

static void
luastream_encode_map(struct luastream *stream, uint32_t size)
{
	lua_createtable(stream->L, size, 0);
}

static void
luastream_encode_uint(struct luastream *stream, uint64_t num)
{
	luaL_pushuint64(stream->L, num);
}

static void
luastream_encode_int(struct luastream *stream, int64_t num)
{
	luaL_pushint64(stream->L, num);
}

static void
luastream_encode_float(struct luastream *stream, float num)
{
	lua_pushnumber(stream->L, num);
}

static void
luastream_encode_double(struct luastream *stream, double num)
{
	lua_pushnumber(stream->L, num);
}

static void
luastream_encode_strn(struct luastream *stream, const char *str, uint32_t len)
{
	lua_pushlstring(stream->L, str, len);
}

static void
luastream_encode_nil(struct luastream *stream)
{
	lua_pushnil(stream->L);
}

static void
luastream_encode_bool(struct luastream *stream, bool val)
{
	lua_pushboolean(stream->L, val);
}

static int
lua_vstream_encode_port(struct vstream *stream, struct port *port)
{
	port_dump_lua(port, ((struct luastream *)stream)->L);
	return 0;
}

static void
lua_vstream_encode_enum(struct vstream *stream, int64_t num, const char *str)
{
	(void)num;
	lua_pushlstring(((struct luastream *)stream)->L, str, strlen(str));
}

static void
lua_vstream_encode_map_commit(struct vstream *stream)
{
	size_t length;
	const char *key = lua_tolstring(((struct luastream *)stream)->L, -2,
					&length);
	lua_setfield(((struct luastream *)stream)->L, -3, key);
	lua_pop(((struct luastream *)stream)->L, 1);
}

static void
lua_vstream_encode_array_commit(struct vstream *stream, uint32_t id)
{
	lua_rawseti(((struct luastream *)stream)->L, -2, id + 1);
}

static const struct vstream_vtab lua_vstream_vtab = {
	/** encode_array = */ (encode_array_f)luastream_encode_array,
	/** encode_map = */ (encode_map_f)luastream_encode_map,
	/** encode_uint = */ (encode_uint_f)luastream_encode_uint,
	/** encode_int = */ (encode_int_f)luastream_encode_int,
	/** encode_float = */ (encode_float_f)luastream_encode_float,
	/** encode_double = */ (encode_double_f)luastream_encode_double,
	/** encode_strn = */ (encode_strn_f)luastream_encode_strn,
	/** encode_nil = */ (encode_nil_f)luastream_encode_nil,
	/** encode_bool = */ (encode_bool_f)luastream_encode_bool,
	/** encode_enum = */ lua_vstream_encode_enum,
	/** encode_port = */ lua_vstream_encode_port,
	/** encode_array_commit = */ lua_vstream_encode_array_commit,
	/** encode_map_commit = */ lua_vstream_encode_map_commit,
};

void
luavstream_init(struct vstream *stream, struct lua_State *L)
{
	stream->vtab = &lua_vstream_vtab;
	assert(sizeof(stream->inheritance_padding) >= sizeof(struct luastream));
	luastream_init((struct luastream *) stream, L);
}
