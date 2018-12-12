/* DO NOT EDIT!
 * This file is automatically generated by the script at
 * ../tool/mkpragmatab.tcl.  To update the set of pragmas, edit
 * that script and rerun it.
 */

/* The various pragma types */
#define PragTyp_BUSY_TIMEOUT                   1
#define PragTyp_CASE_SENSITIVE_LIKE            2
#define PragTyp_COLLATION_LIST                 3
#define PragTyp_FLAG                           5
#define PragTyp_FOREIGN_KEY_LIST               9
#define PragTyp_INDEX_INFO                    10
#define PragTyp_INDEX_LIST                    11
#define PragTyp_STATS                         15
#define PragTyp_TABLE_INFO                    17
#define PragTyp_PARSER_TRACE                  24
#define PragTyp_DEFAULT_ENGINE                25
#define PragTyp_COMPOUND_SELECT_LIMIT         26

/* Property flags associated with various pragma. */
#define PragFlg_NeedSchema 0x01	/* Force schema load before running */
#define PragFlg_NoColumns  0x02	/* OP_ResultRow called with zero columns */
#define PragFlg_NoColumns1 0x04	/* zero columns if RHS argument is present */
#define PragFlg_Result0    0x10	/* Acts as query when no argument */
#define PragFlg_Result1    0x20	/* Acts as query when has one argument */
#define PragFlg_SchemaOpt  0x40	/* Schema restricts name search if present */
#define PragFlg_SchemaReq  0x80	/* Schema required - "main" is default */

/* Names of columns for pragmas that return multi-column result
 * or that return single-column results where the name of the
 * result column is different from the name of the pragma
 */
static const char *const pragCName[] = {
	/* Used by: table_info */
	/*   0 */ "cid",
	/*   1 */ "name",
	/*   2 */ "type",
	/*   3 */ "notnull",
	/*   4 */ "dflt_value",
	/*   5 */ "pk",
	/* Used by: stats */
	/*   6 */ "table",
	/*   7 */ "index",
	/*   8 */ "width",
	/*   9 */ "height",
	/* Used by: index_info */
	/*  10 */ "seqno",
	/*  11 */ "cid",
	/*  12 */ "name",
	/*  13 */ "desc",
	/*  14 */ "coll",
	/*  15 */ "type",
	/* Used by: index_list */
	/*  16 */ "seq",
	/*  17 */ "name",
	/*  18 */ "unique",
	/*  19 */ "origin",
	/*  20 */ "partial",
	/* Used by: collation_list */
	/*  21 */ "seq",
	/*  22 */ "name",
	/* Used by: foreign_key_list */
	/*  23 */ "id",
	/*  24 */ "seq",
	/*  25 */ "table",
	/*  26 */ "from",
	/*  27 */ "to",
	/*  28 */ "on_update",
	/*  29 */ "on_delete",
	/*  30 */ "match",
	/* Used by: busy_timeout */
	/*  31 */ "timeout",
};

/* Definitions of all built-in pragmas */
typedef struct PragmaName {
	const char *const zName;	/* Name of pragma */
	u8 ePragTyp;		/* PragTyp_XXX value */
	u8 mPragFlg;		/* Zero or more PragFlg_XXX values */
	u8 iPragCName;		/* Start of column names in pragCName[] */
	u8 nPragCName;		/* Num of col names. 0 means use pragma name */
	u32 iArg;		/* Extra argument */
} PragmaName;
/**
 * The order of pragmas in this array is important: it has
 * to be sorted. For more info see pragma_locate function.
 */
static const PragmaName aPragmaName[] = {
	{ /* zName:     */ "busy_timeout",
	 /* ePragTyp:  */ PragTyp_BUSY_TIMEOUT,
	 /* ePragFlg:  */ PragFlg_Result0,
	 /* ColNames:  */ 31, 1,
	 /* iArg:      */ 0},
	{ /* zName:     */ "case_sensitive_like",
	 /* ePragTyp:  */ PragTyp_CASE_SENSITIVE_LIKE,
	 /* ePragFlg:  */ PragFlg_NoColumns,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ 0},
	{ /* zName:     */ "collation_list",
	 /* ePragTyp:  */ PragTyp_COLLATION_LIST,
	 /* ePragFlg:  */ PragFlg_Result0,
	 /* ColNames:  */ 21, 2,
	 /* iArg:      */ 0},
	{ /* zName:     */ "count_changes",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_CountRows},
	{ /* zName:     */ "defer_foreign_keys",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_DeferFKs},
	{ /* zName:     */ "foreign_key_list",
	 /* ePragTyp:  */ PragTyp_FOREIGN_KEY_LIST,
	 /* ePragFlg:  */
	 PragFlg_NeedSchema | PragFlg_Result1 | PragFlg_SchemaOpt,
	 /* ColNames:  */ 23, 8,
	 /* iArg:      */ 0},
	{ /* zName:     */ "full_column_names",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_FullColNames},
	{ /* zName:     */ "index_info",
	 /* ePragTyp:  */ PragTyp_INDEX_INFO,
	 /* ePragFlg:  */
	 PragFlg_NeedSchema | PragFlg_Result1 | PragFlg_SchemaOpt,
	 /* ColNames:  */ 10, 6,
	 /* iArg:      */ 1},
	{ /* zName:     */ "index_list",
	 /* ePragTyp:  */ PragTyp_INDEX_LIST,
	 /* ePragFlg:  */
	 PragFlg_NeedSchema | PragFlg_Result1 | PragFlg_SchemaOpt,
	 /* ColNames:  */ 16, 5,
	 /* iArg:      */ 0},
#if defined(SQLITE_DEBUG)
	{ /* zName:     */ "parser_trace",
	 /* ePragTyp:  */ PragTyp_PARSER_TRACE,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_ParserTrace},
#endif
	{ /* zName:     */ "query_only",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_QueryOnly},
	{ /* zName:     */ "read_uncommitted",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_ReadUncommitted},
	{ /* zName:     */ "recursive_triggers",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_RecTriggers},
	{ /* zName:     */ "reverse_unordered_selects",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_ReverseOrder},
#if defined(SQLITE_ENABLE_SELECTTRACE)
	{ /* zName:     */ "select_trace",
	/* ePragTyp:  */ PragTyp_FLAG,
	/* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	/* ColNames:  */ 0, 0,
	/* iArg:      */ SQLITE_SelectTrace},
#endif
	{ /* zName:     */ "short_column_names",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_ShortColNames},
	{ /* zName:     */ "sql_compound_select_limit",
	/* ePragTyp:  */ PragTyp_COMPOUND_SELECT_LIMIT,
	/* ePragFlg:  */ PragFlg_Result0,
	/* ColNames:  */ 0, 0,
	/* iArg:      */ 0},
	{ /* zName:     */ "sql_default_engine",
	 /* ePragTyp:  */ PragTyp_DEFAULT_ENGINE,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ 0},
#if defined(SQLITE_DEBUG)
	{ /* zName:     */ "sql_trace",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_SqlTrace},
#endif
	{ /* zName:     */ "stats",
	 /* ePragTyp:  */ PragTyp_STATS,
	 /* ePragFlg:  */
	 PragFlg_NeedSchema | PragFlg_Result0 | PragFlg_SchemaReq,
	 /* ColNames:  */ 6, 4,
	 /* iArg:      */ 0},
	{ /* zName:     */ "table_info",
	 /* ePragTyp:  */ PragTyp_TABLE_INFO,
	 /* ePragFlg:  */
	 PragFlg_NeedSchema | PragFlg_Result1 | PragFlg_SchemaOpt,
	 /* ColNames:  */ 0, 6,
	 /* iArg:      */ 0},
#if defined(SQLITE_DEBUG)
	{ /* zName:     */ "vdbe_addoptrace",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_VdbeAddopTrace},
	{ /* zName:     */ "vdbe_debug",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */
	 SQLITE_SqlTrace | SQLITE_VdbeListing | SQLITE_VdbeTrace},
	{ /* zName:     */ "vdbe_eqp",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_VdbeEQP},
	{ /* zName:     */ "vdbe_listing",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_VdbeListing},
	{ /* zName:     */ "vdbe_trace",
	 /* ePragTyp:  */ PragTyp_FLAG,
	 /* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	 /* ColNames:  */ 0, 0,
	 /* iArg:      */ SQLITE_VdbeTrace},
#endif
#if defined(SQLITE_ENABLE_WHERETRACE)

	{ /* zName:     */ "where_trace",
	/* ePragTyp:  */ PragTyp_FLAG,
	/* ePragFlg:  */ PragFlg_Result0 | PragFlg_NoColumns1,
	/* ColNames:  */ 0, 0,
	/* iArg:      */ SQLITE_WhereTrace},
#endif
};
/* Number of pragmas: 36 on by default, 47 total. */
