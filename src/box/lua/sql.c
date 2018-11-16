#include "sql.h"
#include "box/sql.h"
#include "lua/msgpack.h"

#include "box/sql/sqliteInt.h"
#include "box/info.h"
#include "lua/utils.h"
#include "lua/luastream.h"
#include "info.h"
#include "box/execute.h"
#include "vstream.h"

static int
lbox_execute(struct lua_State *L)
{
	struct sqlite3 *db = sql_get();
	if (db == NULL)
		return luaL_error(L, "not ready");

	size_t length;
	const char *sql = lua_tolstring(L, 1, &length);
	if (sql == NULL)
		return luaL_error(L, "usage: box.execute(sqlstring)");

	struct sql_request request = {};
	request.sql_text = sql;
	request.sql_text_len = length;
	if (lua_gettop(L) == 2 && lua_sql_bind_list_decode(L, &request, 2) != 0)
		goto sqlerror;

	struct sql_response response = {.is_info_flattened = true};
	if (sql_prepare_and_execute(&request, &response, &fiber()->gc,
				    ER_SYSTEM) != 0)
		goto sqlerror;

	int keys;
	struct vstream vstream;
	luavstream_init(&vstream, L);
	lua_newtable(L);
	if (sql_response_dump(&response, &keys, &vstream) != 0) {
		lua_pop(L, 1);
		goto sqlerror;
	}
	return 1;
sqlerror:
	lua_pushstring(L, sqlite3_errmsg(db));
	return lua_error(L);
}

static int
lua_sql_debug(struct lua_State *L)
{
	struct info_handler info;
	luaT_info_handler_create(&info, L);
	sql_debug_info(&info);
	return 1;
}

void
box_lua_sqlite_init(struct lua_State *L)
{
	static const struct luaL_Reg module_funcs [] = {
		{"new_execute", lbox_execute},
		{"debug", lua_sql_debug},
		{NULL, NULL}
	};

	/* used by lua_sql_execute via upvalue */
	lua_createtable(L, 0, 1);
	lua_pushstring(L, "sequence");
	lua_setfield(L, -2, "__serialize");

	luaL_openlib(L, "box.sql", module_funcs, 1);
	lua_pop(L, 1);
}

