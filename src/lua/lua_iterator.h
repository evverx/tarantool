#ifndef TARANTOOL_LUA_LUA_ITERATOR_H_INCLUDED
#define TARANTOOL_LUA_LUA_ITERATOR_H_INCLUDED 1
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
 * THIS SOFTWARE IS PROVIDED BY AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
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
 * This module contains helper functions to interact with a Lua
 * iterator from C.
 */

#include <lua.h>

/**
 * Holds iterator state (references to Lua objects).
 */
struct lua_iterator {
	int gen;
	int param;
	int state;
};

/**
 * Create a Lua iterator from {gen, param, state}.
 */
struct lua_iterator *
lua_iterator_new_fromtable(lua_State *L, int idx)
{
	struct lua_iterator *it = (struct lua_iterator *) malloc(
		sizeof(struct lua_iterator));

	lua_rawgeti(L, idx, 1); /* Popped by luaL_ref(). */
	it->gen = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_rawgeti(L, idx, 2); /* Popped by luaL_ref(). */
	it->param = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_rawgeti(L, idx, 3); /* Popped by luaL_ref(). */
	it->state = luaL_ref(L, LUA_REGISTRYINDEX);

	return it;
}

/**
 * Move iterator to the next value. Push values returned by
 * gen(param, state) and return its count. Zero means no more
 * results available.
 */
int
lua_iterator_next(lua_State *L, struct lua_iterator *it)
{
	int frame_start = lua_gettop(L);

	/* Call gen(param, state). */
	lua_rawgeti(L, LUA_REGISTRYINDEX, it->gen);
	lua_rawgeti(L, LUA_REGISTRYINDEX, it->param);
	lua_rawgeti(L, LUA_REGISTRYINDEX, it->state);
	lua_call(L, 2, LUA_MULTRET);
	int nresults = lua_gettop(L) - frame_start;
	if (nresults == 0) {
		luaL_error(L, "lua_iterator_next: gen(param, state) must "
			      "return at least one result");
		unreachable();
		return 0;
	}

	/* The call above returns nil as the first result. */
	if (lua_isnil(L, frame_start + 1)) {
		lua_settop(L, frame_start);
		return 0;
	}

	/* Save the first result to it->state. */
	luaL_unref(L, LUA_REGISTRYINDEX, it->state);
	lua_pushvalue(L, frame_start + 1); /* Popped by luaL_ref(). */
	it->state = luaL_ref(L, LUA_REGISTRYINDEX);

	return nresults;
}

/**
 * Free all resources hold by the iterator.
 */
void lua_iterator_free(lua_State *L, struct lua_iterator *it)
{
	luaL_unref(L, LUA_REGISTRYINDEX, it->gen);
	luaL_unref(L, LUA_REGISTRYINDEX, it->param);
	luaL_unref(L, LUA_REGISTRYINDEX, it->state);
	free(it);
}

#endif /* TARANTOOL_LUA_LUA_ITERATOR_H_INCLUDED */
