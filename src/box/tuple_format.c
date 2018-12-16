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
#include "fiber.h"
#include "json/json.h"
#include "tuple_format.h"
#include "coll_id_cache.h"

/** Global table of tuple formats */
struct tuple_format **tuple_formats;
static intptr_t recycled_format_ids = FORMAT_ID_NIL;

static uint32_t formats_size = 0, formats_capacity = 0;
static uint64_t formats_epoch = 0;

static struct tuple_field *
tuple_field_new(void)
{
	struct tuple_field *field = calloc(1, sizeof(struct tuple_field));
	if (field == NULL) {
		diag_set(OutOfMemory, sizeof(struct tuple_field), "malloc",
			 "tuple field");
		return NULL;
	}
	field->token.type = JSON_TOKEN_END;
	field->type = FIELD_TYPE_ANY;
	field->offset_slot = TUPLE_OFFSET_SLOT_NIL;
	field->coll_id = COLL_NONE;
	field->nullable_action = ON_CONFLICT_ACTION_NONE;
	return field;
}

static void
tuple_field_delete(struct tuple_field *field)
{
	free(field);
}

/** Build the JSON path by field specified. */
static const char *
tuple_field_json_path(const struct tuple_format *format,
		      struct tuple_field *field,
		      struct region *region)
{
	/* Don't put brackets for first-level fields. */
	bool brackets = true;
	if (field->token.parent == &format->fields.root)
		brackets = false;

	uint32_t token_path_sz = sizeof(void *)*format->max_path_tokens;
	uint32_t token_path_len = 0;
	struct json_token **token_path = region_alloc(region, token_path_sz);
	if (token_path == NULL) {
		diag_set(OutOfMemory, token_path_sz, "region_alloc",
			 "token_path");
		return NULL;
	}
	uint32_t path_size = 1;
	struct json_token *token = &field->token;
	while (token != &format->fields.root) {
		token_path[token_path_len++] = token;
		if (token->parent == &format->fields.root &&
		    token->num < (int)format->dict->name_count) {
			const char *field_name =
				format->dict->names[token->num];
			path_size += 4 + strlen(field_name);
		} else if (token->type == JSON_TOKEN_NUM) {
			uint32_t digits = 0;
			for (int num = token->num + TUPLE_INDEX_BASE; num > 0;
			     num /= 10)
				digits++;
			path_size += 2 + digits;
		} else if (token->type == JSON_TOKEN_STR) {
			path_size += 4 + token->len;
		} else {
			unreachable();
		}
		token = token->parent;
	}
	char *path = region_alloc(region, path_size);
	if (path == NULL) {
		diag_set(OutOfMemory, path_size, "region_alloc", "path");
		return NULL;
	}
	char *wptr = path;
	for (int i = token_path_len - 1; i >= 0; i--) {
		token = token_path[i];
		if (token->parent == &format->fields.root &&
		    token->num < (int)format->dict->name_count) {
			const char *field_name =
				format->dict->names[token->num];
			wptr += sprintf(wptr, brackets ? "[\"%s\"]" : "\"%s\"",
					field_name);
		} else if (token->type == JSON_TOKEN_NUM) {
			wptr += sprintf(wptr, brackets ? "[%u]" : "%u",
					token->num + TUPLE_INDEX_BASE);
		} else if (token->type == JSON_TOKEN_STR) {
			wptr += sprintf(wptr, "[\"%.*s\"]", token->len,
					token->str);
		} else {
			unreachable();
		}
	}
	*wptr = '\0';
	return path;
}

/** Build a JSON tree path for specified path. */
static struct tuple_field *
tuple_field_tree_add_path(struct tuple_format *format, const char *path,
			  uint32_t path_len, uint32_t fieldno)
{
	int rc = 0;
	struct json_tree *tree = &format->fields;
	struct tuple_field *parent = tuple_format_field(format, fieldno);
	struct tuple_field *field = tuple_field_new();
	if (field == NULL)
		goto fail;

	struct json_lexer lexer;
	uint32_t token_count = 0;
	json_lexer_create(&lexer, path, path_len, TUPLE_INDEX_BASE);
	while ((rc = json_lexer_next_token(&lexer, &field->token)) == 0 &&
	       field->token.type != JSON_TOKEN_END) {
		enum field_type expected_type =
			field->token.type == JSON_TOKEN_STR ?
			FIELD_TYPE_MAP : FIELD_TYPE_ARRAY;
		if (parent->type != FIELD_TYPE_ANY &&
		    parent->type != expected_type) {
			/* Parent field has incompatable type. */
			const char *path = tuple_field_json_path(format, parent,
								 &fiber()->gc);
			if (path != NULL) {
				diag_set(ClientError,
					 ER_INDEX_PART_TYPE_MISMATCH, path,
					 field_type_strs[parent->type],
					 field_type_strs[expected_type]);
			}
			goto fail;
		}
		struct tuple_field *next =
			json_tree_lookup_entry(tree, &parent->token,
					       &field->token,
					       struct tuple_field, token);
		if (next == NULL) {
			rc = json_tree_add(tree, &parent->token, &field->token);
			if (rc != 0) {
				diag_set(OutOfMemory, sizeof(struct json_token),
					 "json_tree_add", "tree");
				goto fail;
			}
			next = field;
			field = tuple_field_new();
			if (field == NULL)
				goto fail;
		}
		parent->type = expected_type;
		parent = next;
		token_count++;
	}
	assert(rc == 0 && field->token.type == JSON_TOKEN_END);
	assert(parent != NULL);
	/* Update tree depth information. */
	format->max_path_tokens = MAX(format->max_path_tokens, token_count + 1);
end:
	tuple_field_delete(field);
	return parent;
fail:
	parent = NULL;
	goto end;
}

static int
tuple_format_use_key_part(struct tuple_format *format, uint32_t field_count,
			  const struct key_part *part, bool is_sequential,
			  int *current_slot, char **path_data)
{
	assert(part->fieldno < tuple_format_field_count(format));
	struct tuple_field *field;
	if (part->path == NULL) {
		field = tuple_format_field(format, part->fieldno);
	} else {
		assert(!is_sequential);
		/**
		 * Copy JSON path data to reserved area at the
		 * end of format allocation.
		 */
		memcpy(*path_data, part->path, part->path_len);
		field = tuple_field_tree_add_path(format, *path_data,
						  part->path_len,
						  part->fieldno);
		if (field == NULL)
			return -1;
		*path_data += part->path_len;
	}
	/*
		* If a field is not present in the space format,
		* inherit nullable action of the first key part
		* referencing it.
		*/
	if (part->fieldno >= field_count && !field->is_key_part)
		field->nullable_action = part->nullable_action;
	/*
	 * Field and part nullable actions may differ only
	 * if one of them is DEFAULT, in which case we use
	 * the non-default action *except* the case when
	 * the other one is NONE, in which case we assume
	 * DEFAULT. The latter is needed so that in case
	 * index definition and space format have different
	 * is_nullable flag, we will use the strictest option,
	 * i.e. DEFAULT.
	 */
	if (field->nullable_action == ON_CONFLICT_ACTION_DEFAULT) {
		if (part->nullable_action != ON_CONFLICT_ACTION_NONE)
			field->nullable_action = part->nullable_action;
	} else if (part->nullable_action == ON_CONFLICT_ACTION_DEFAULT) {
		if (field->nullable_action == ON_CONFLICT_ACTION_NONE)
			field->nullable_action = part->nullable_action;
	} else if (field->nullable_action != part->nullable_action) {
		const char *path = tuple_field_json_path(format, field,
							 &fiber()->gc);
		if (path != NULL) {
			diag_set(ClientError, ER_ACTION_MISMATCH, path,
				 on_conflict_action_strs[field->nullable_action],
				 on_conflict_action_strs[part->nullable_action]);
		}
		return -1;
	}

	/**
	 * Check that there are no conflicts between index part
	 * types and space fields. If a part type is compatible
	 * with field's one, then the part type is more strict
	 * and the part type must be used in tuple_format.
	 */
	if (field_type1_contains_type2(field->type,
					part->type)) {
		field->type = part->type;
	} else if (!field_type1_contains_type2(part->type,
					       field->type)) {
		int errcode;
		if (!field->is_key_part)
			errcode = ER_FORMAT_MISMATCH_INDEX_PART;
		else
			errcode = ER_INDEX_PART_TYPE_MISMATCH;
		const char *path = tuple_field_json_path(format, field,
							 &fiber()->gc);
		if (path != NULL) {
			diag_set(ClientError, errcode, path,
				 field_type_strs[field->type],
				 field_type_strs[part->type]);
		}
		return -1;
	}
	field->is_key_part = true;
	/*
	 * In the tuple, store only offsets necessary to access
	 * fields of non-sequential keys. First field is always
	 * simply accessible, so we don't store an offset for it.
	 */
	if (field->offset_slot == TUPLE_OFFSET_SLOT_NIL &&
	    is_sequential == false &&
	    (part->fieldno > 0 || part->path != NULL)) {
		*current_slot = *current_slot - 1;
		field->offset_slot = *current_slot;
	}
	return 0;
}

/**
 * Extract all available type info from keys and field
 * definitions.
 */
static int
tuple_format_create(struct tuple_format *format, struct key_def * const *keys,
		    uint16_t key_count, const struct field_def *fields,
		    uint32_t field_count)
{
	format->min_field_count =
		tuple_format_min_field_count(keys, key_count, fields,
					     field_count);
	if (tuple_format_field_count(format) == 0) {
		format->field_map_size = 0;
		return 0;
	}
	/* Initialize defined fields */
	for (uint32_t i = 0; i < field_count; ++i) {
		struct tuple_field *field = tuple_format_field(format, i);
		field->type = fields[i].type;
		field->nullable_action = fields[i].nullable_action;
		struct coll *coll = NULL;
		uint32_t cid = fields[i].coll_id;
		if (cid != COLL_NONE) {
			struct coll_id *coll_id = coll_by_id(cid);
			if (coll_id == NULL) {
				diag_set(ClientError,ER_WRONG_COLLATION_OPTIONS,
					 i + 1, "collation was not found by ID");
				return -1;
			}
			coll = coll_id->coll;
		}
		field->coll = coll;
		field->coll_id = cid;
	}

	int current_slot = 0;

	char *paths_data = (char *)format + sizeof(struct tuple_format);
	/* extract field type info */
	for (uint16_t key_no = 0; key_no < key_count; ++key_no) {
		const struct key_def *key_def = keys[key_no];
		bool is_sequential = key_def_is_sequential(key_def);
		const struct key_part *part = key_def->parts;
		const struct key_part *parts_end = part + key_def->part_count;

		for (; part < parts_end; part++) {
			if (tuple_format_use_key_part(format, field_count, part,
						      is_sequential,
						      &current_slot,
						      &paths_data) != 0)
				return -1;
		}
	}

	assert(tuple_format_field(format, 0)->offset_slot ==
	       TUPLE_OFFSET_SLOT_NIL);
	size_t field_map_size = -current_slot * sizeof(uint32_t);
	if (field_map_size > UINT16_MAX) {
		/** tuple->data_offset is 16 bits */
		diag_set(ClientError, ER_INDEX_FIELD_COUNT_LIMIT,
			 -current_slot);
		return -1;
	}
	format->field_map_size = field_map_size;
	/**
	 * Allocate field_map_template used for field map
	 * initialization and validation.
	 * Read tuple_format:field_map_template description for
	 * more details.
	 */
	uint32_t *field_map_template = malloc(field_map_size);
	if (field_map_template == NULL) {
		diag_set(OutOfMemory, field_map_size, "malloc",
			 "field_map_template");
		return -1;
	}
	format->field_map_template = field_map_template;
	/*
	 * Mark all template_field_map items as uninitialized
	 * with UINT32_MAX magic value.
	 */
	field_map_template = (uint32_t *)((char *)field_map_template +
					  format->field_map_size);
	for (int i = -1; i >= current_slot; i--)
		field_map_template[i] = UINT32_MAX;
	int id = 0;
	struct tuple_field *field;
	struct json_token *root = (struct json_token *)&format->fields.root;
	json_tree_foreach_entry_preorder(field, root, struct tuple_field,
					 token) {
		/*
		 * Initialize nullable fields in
		 * field_map_template with 0 as we shouldn't
		 * raise error when field_map item for nullable
		 * field was not calculated during tuple parse
		 * (when tuple lacks such field).
		 */
		if (field->offset_slot != TUPLE_OFFSET_SLOT_NIL &&
		    tuple_field_is_nullable(field))
			field_map_template[field->offset_slot] = 0;

		/*
		 * Estimate the size of vy_stmt secondary key
		 * tuple. All leaf records are assumed to be
		 * nil(s).
		 */
		int size = 0;
		struct json_token *curr_node = &field->token;
		enum field_type parent_type =
			curr_node->parent == &format->fields.root ?
			FIELD_TYPE_ARRAY :
			json_tree_entry(curr_node->parent, struct tuple_field,
					token)->type;
		if (parent_type == FIELD_TYPE_ARRAY) {
			/*
			 * Account a gap between neighboring
			 * fields filled with nil(s) when parent
			 * field type is FIELD_TYPE_ARRAY.
			 */
			int nulls = 0;
			for (int i = field->token.sibling_idx - 1;
			     i > 0 && curr_node->parent->children[i] == NULL;
			     i--)
				nulls++;
			size += nulls * mp_sizeof_nil();
		} else if (parent_type == FIELD_TYPE_MAP) {
			/*
			 * Account memory required for map key
			 * string when parent field type is
			 * FIELD_TYPE_MAP.
			 */
			size += mp_sizeof_str(field->token.len);
		}
		if (field->token.max_child_idx == -1) {
			size += mp_sizeof_nil();
		} else if (field->type == FIELD_TYPE_ARRAY) {
			size += mp_sizeof_array(field->token.max_child_idx);
		} else if (field->type == FIELD_TYPE_MAP) {
			size += mp_sizeof_map(field->token.max_child_idx);
		}
		format->vy_stmt_meta_size += size;

		/* Assign unique identifier for each field. */
		field->id = id++;
	}
	/* Total amount of fields in format. */
	format->total_field_count = id;
	return 0;
}

static int
tuple_format_register(struct tuple_format *format)
{
	if (recycled_format_ids != FORMAT_ID_NIL) {

		format->id = (uint16_t) recycled_format_ids;
		recycled_format_ids = (intptr_t) tuple_formats[recycled_format_ids];
	} else {
		if (formats_size == formats_capacity) {
			uint32_t new_capacity = formats_capacity ?
						formats_capacity * 2 : 16;
			struct tuple_format **formats;
			formats = (struct tuple_format **)
				realloc(tuple_formats, new_capacity *
						       sizeof(tuple_formats[0]));
			if (formats == NULL) {
				diag_set(OutOfMemory,
					 sizeof(struct tuple_format), "malloc",
					 "tuple_formats");
				return -1;
			}

			formats_capacity = new_capacity;
			tuple_formats = formats;
		}
		if (formats_size == FORMAT_ID_MAX + 1) {
			diag_set(ClientError, ER_TUPLE_FORMAT_LIMIT,
				 (unsigned) formats_capacity);
			return -1;
		}
		format->id = formats_size++;
	}
	tuple_formats[format->id] = format;
	return 0;
}

static void
tuple_format_deregister(struct tuple_format *format)
{
	if (format->id == FORMAT_ID_NIL)
		return;
	tuple_formats[format->id] = (struct tuple_format *) recycled_format_ids;
	recycled_format_ids = format->id;
	format->id = FORMAT_ID_NIL;
}

/*
 * Dismantle the tuple field tree attached to the format and free
 * memory occupied by tuple fields.
 */
static void
tuple_format_destroy_fields(struct tuple_format *format)
{
	struct tuple_field *field, *tmp;
	json_tree_foreach_entry_safe(field, &format->fields.root,
				     struct tuple_field, token, tmp) {
		json_tree_del(&format->fields, &field->token);
		tuple_field_delete(field);
	}
	json_tree_destroy(&format->fields);
}

static struct tuple_format *
tuple_format_alloc(struct key_def * const *keys, uint16_t key_count,
		   uint32_t space_field_count, struct tuple_dictionary *dict)
{
	/* Size of area to store paths. */
	uint32_t paths_size = 0;
	uint32_t index_field_count = 0;
	/* find max max field no */
	for (uint16_t key_no = 0; key_no < key_count; ++key_no) {
		const struct key_def *key_def = keys[key_no];
		const struct key_part *part = key_def->parts;
		const struct key_part *pend = part + key_def->part_count;
		for (; part < pend; part++) {
			index_field_count = MAX(index_field_count,
						part->fieldno + 1);
			paths_size += part->path_len;
		}
	}
	uint32_t field_count = MAX(space_field_count, index_field_count);

	uint32_t allocation_size = sizeof(struct tuple_format) + paths_size;
	struct tuple_format *format = malloc(allocation_size);
	if (format == NULL) {
		diag_set(OutOfMemory, allocation_size, "malloc",
			 "tuple format");
		return NULL;
	}
	if (json_tree_create(&format->fields) != 0) {
		diag_set(OutOfMemory, 0, "json_lexer_create",
			 "tuple field tree");
		free(format);
		return NULL;
	}
	for (uint32_t fieldno = 0; fieldno < field_count; fieldno++) {
		struct tuple_field *field = tuple_field_new();
		if (field == NULL)
			goto error;
		field->id = fieldno;
		field->token.num = fieldno;
		field->token.type = JSON_TOKEN_NUM;
		if (json_tree_add(&format->fields, &format->fields.root,
				  &field->token) != 0) {
			diag_set(OutOfMemory, 0, "json_tree_add",
				 "tuple field tree entry");
			tuple_field_delete(field);
			goto error;
		}
	}
	if (dict == NULL) {
		assert(space_field_count == 0);
		format->dict = tuple_dictionary_new(NULL, 0);
		if (format->dict == NULL)
			goto error;
	} else {
		format->dict = dict;
		tuple_dictionary_ref(dict);
	}
	format->max_path_tokens = 1;
	format->total_field_count = field_count;
	format->vy_stmt_meta_size = 0;
	format->refs = 0;
	format->id = FORMAT_ID_NIL;
	format->index_field_count = index_field_count;
	format->exact_field_count = 0;
	format->min_field_count = 0;
	format->field_map_template = NULL;
	return format;
error:
	tuple_format_destroy_fields(format);
	free(format);
	return NULL;
}

/** Free tuple format resources, doesn't unregister. */
static inline void
tuple_format_destroy(struct tuple_format *format)
{
	free(format->field_map_template);
	tuple_format_destroy_fields(format);
	tuple_dictionary_unref(format->dict);
}

void
tuple_format_delete(struct tuple_format *format)
{
	tuple_format_deregister(format);
	tuple_format_destroy(format);
	free(format);
}

struct tuple_format *
tuple_format_new(struct tuple_format_vtab *vtab, struct key_def * const *keys,
		 uint16_t key_count, const struct field_def *space_fields,
		 uint32_t space_field_count, struct tuple_dictionary *dict)
{
	struct tuple_format *format =
		tuple_format_alloc(keys, key_count, space_field_count, dict);
	if (format == NULL)
		return NULL;
	format->vtab = *vtab;
	format->engine = NULL;
	format->is_temporary = false;
	format->epoch = ++formats_epoch;
	if (tuple_format_register(format) < 0) {
		tuple_format_destroy(format);
		free(format);
		return NULL;
	}
	if (tuple_format_create(format, keys, key_count, space_fields,
				space_field_count) < 0) {
		tuple_format_delete(format);
		return NULL;
	}
	return format;
}

bool
tuple_format1_can_store_format2_tuples(struct tuple_format *format1,
				       struct tuple_format *format2)
{
	if (format1->exact_field_count != format2->exact_field_count)
		return false;
	struct tuple_field *field1;
	struct json_token *field2_prev_token = &format2->fields.root;
	struct json_token *field1_prev_token = &format1->fields.root;
	json_tree_foreach_entry_preorder(field1, &format1->fields.root,
					 struct tuple_field, token) {
next:
		/*
		 * While switching to the next item, it may be
		 * necessary to update the parents of both tree
		 * iterators.
		 */
		while (field1_prev_token != field1->token.parent) {
			field1_prev_token = field1_prev_token->parent;
			field2_prev_token = field2_prev_token->parent;
			assert(field1_prev_token != NULL);
		}
		struct tuple_field *field2 =
			json_tree_lookup_entry(&format2->fields,
						field2_prev_token,
						&field1->token,
						struct tuple_field, token);
		/*
		 * The field has a data type in format1, but has
		 * no data type in format2.
		 */
		if (field2 == NULL) {
			/*
			 * The field can get a name added
			 * for it, and this doesn't require a data
			 * check.
			 * If the field is defined as not
			 * nullable, however, we need a data
			 * check, since old data may contain
			 * NULLs or miss the subject field.
			 */
			if (field1->type == FIELD_TYPE_ANY &&
			    tuple_field_is_nullable(field1)) {
				/* Skip subtree. */
				struct json_token *root = &format1->fields.root;
				struct json_token *next =
					json_tree_preorder_next(root,
								&field1->token);
				field1 = json_tree_entry_safe(next,
							      struct tuple_field,
							      token);
				if (field1 == NULL)
					break;
				goto next;
			} else {
				return false;
			}
		}
		if (! field_type1_contains_type2(field1->type, field2->type))
			return false;
		/*
		 * Do not allow transition from nullable to non-nullable:
		 * it would require a check of all data in the space.
		 */
		if (tuple_field_is_nullable(field2) &&
		    !tuple_field_is_nullable(field1))
			return false;

		field2_prev_token = &field2->token;
		field1_prev_token = &field1->token;
	}
	return true;
}

/** Find a field in format by offset slot. */
static struct tuple_field *
tuple_field_by_offset_slot(const struct tuple_format *format,
			   int32_t offset_slot)
{
	struct tuple_field *field;
	struct json_token *root = (struct json_token *)&format->fields.root;
	json_tree_foreach_entry_preorder(field, root, struct tuple_field,
					 token) {
		if (field->offset_slot == offset_slot)
			return field;
	}
	return NULL;
}

/**
 * Verify that all offset_slots has been initialized in field_map.
 * Routine relies on the field_map memory has been filled from the
 * field_map_template containing UINT32_MAX marker for required
 * fields.
 */
static int
tuple_field_map_validate(const struct tuple_format *format, uint32_t *field_map)
{
	int32_t field_map_items =
		(int32_t)(format->field_map_size/sizeof(field_map[0]));
	for (int32_t i = -1; i >= -field_map_items; i--) {
		if (field_map[i] != UINT32_MAX)
			continue;

		struct tuple_field *field =
			tuple_field_by_offset_slot(format, i);
		assert(field != NULL);
		/* Lookup for field number in tree. */
		const char *path =
			tuple_field_json_path(format, field, &fiber()->gc);
		if (path == NULL)
			return -1;

		struct json_token *token = &field->token;
		const char *err_msg;
		if (field->token.type == JSON_TOKEN_STR) {
			err_msg = tt_sprintf("invalid field \"%s\" document "
					     "content: map doesn't contain a "
					     "key '%.*s' defined in index",
					     path, token->len, token->str);
		} else if (field->token.type == JSON_TOKEN_NUM) {
			uint32_t expected_size =
				token->parent->max_child_idx + 1;
			err_msg = tt_sprintf("invalid field \"%s\" document "
					     "content: array size %d is less "
					     "than size %d defined in index",
					     path, token->num, expected_size);
		}
		diag_set(ClientError, ER_DATA_STRUCTURE_MISMATCH, err_msg);
		return -1;
	}
	return 0;
}

/** Checks if mp_type (MsgPack) is compatible with field type. */
static inline bool
mp_type_is_compatible(enum mp_type mp_type, enum field_type type,
		      bool is_nullable)
{
	assert(type < field_type_MAX);
	assert((size_t) mp_type < CHAR_BIT * sizeof(*key_mp_type));
	uint32_t mask = key_mp_type[type] | (is_nullable * (1U << MP_NIL));
	return (mask & (1U << mp_type)) != 0;
}

/**
 * Descriptor of the parsed msgpack frame.
 * Due to the fact that the msgpack has nested structures whose
 * length is stored in the frame header at the blob beginning, we
 * need to be able to determine that we have finished parsing the
 * current component and should move on to the next one.
 * For this purpose a stack of disassembled levels is organized,
 * where the type of the level, the total number of elements,
 * and the number of elements that have already been parsed are
 * stored.
 */
struct mp_frame {
	/** JSON token type representing frame data structure. */
	enum json_token_type child_type;
	/** Total count of MP members to process. */
	uint32_t total;
	/** Count of MP elements that already have parseed. */
	uint32_t curr;
};

/**
 * Emit token to analyze and do msgpack pointer shift using top
 * mp_stack frame. Return 0 on success, -1 when analyse step must
 * be skipped (on usuported term detection).
 */
static int
mp_frame_parse(struct mp_frame *mp_stack, uint32_t mp_stack_idx,
	       const char **pos, struct json_token *token)
{
	token->type = mp_stack[mp_stack_idx].child_type;
	++mp_stack[mp_stack_idx].curr;
	if (token->type == JSON_TOKEN_NUM) {
		token->num = mp_stack[mp_stack_idx].curr - TUPLE_INDEX_BASE;
	} else if (token->type == JSON_TOKEN_STR) {
		if (mp_typeof(**pos) != MP_STR) {
			/* Skip key. */
			mp_next(pos);
			return -1;
		}
		token->str = mp_decode_str(pos, (uint32_t *)&token->len);
	} else {
		unreachable();
	}
	return 0;
}

/**
 * Prepare mp_frame for futher iterations. Store container length
 * and child_type. Update parent token pointer and shift msgpack
 * pointer.
 */
static int
mp_frame_prepare(struct mp_frame *mp_stack, uint32_t *mp_stack_idx,
		 uint32_t mp_stack_total, struct json_token *token,
		 const char **pos, struct json_token **parent)
{
	enum mp_type type = mp_typeof(**pos);
	if (token != NULL && *mp_stack_idx + 1 < mp_stack_total &&
	    (type == MP_MAP || type == MP_ARRAY)) {
		uint32_t size = type == MP_ARRAY ? mp_decode_array(pos) :
				mp_decode_map(pos);
		if (size == 0)
			return 0;
		*parent = token;
		enum json_token_type child_type =
			type == MP_ARRAY ? JSON_TOKEN_NUM : JSON_TOKEN_STR;
		*mp_stack_idx = *mp_stack_idx + 1;
		mp_stack[*mp_stack_idx].child_type = child_type;
		mp_stack[*mp_stack_idx].total = size;
		mp_stack[*mp_stack_idx].curr = 0;
	} else {
		mp_next(pos);
		while (mp_stack[*mp_stack_idx].curr >=
			mp_stack[*mp_stack_idx].total) {
			assert(*parent != NULL);
			*parent = (*parent)->parent;
			if (*mp_stack_idx == 0)
				return -1;
			*mp_stack_idx = *mp_stack_idx - 1;
		}
	}
	return 0;
}

/** @sa declaration for details. */
int
tuple_init_field_map(const struct tuple_format *format, uint32_t *field_map,
		     const char *tuple, bool validate)
{
	if (tuple_format_field_count(format) == 0)
		return 0; /* Nothing to initialize */

	const char *pos = tuple;

	/* Check to see if the tuple has a sufficient number of fields. */
	uint32_t field_count = mp_decode_array(&pos);
	if (validate && format->exact_field_count > 0 &&
	    format->exact_field_count != field_count) {
		diag_set(ClientError, ER_EXACT_FIELD_COUNT,
			 (unsigned) field_count,
			 (unsigned) format->exact_field_count);
		return -1;
	}
	if (validate && field_count < format->min_field_count) {
		diag_set(ClientError, ER_MIN_FIELD_COUNT,
			 (unsigned) field_count,
			 (unsigned) format->min_field_count);
		return -1;
	}
	uint32_t defined_field_count = MIN(field_count, validate ?
					   tuple_format_field_count(format) :
					   format->index_field_count);
	/*
	 * Initialize memory with zeros when no validation is
	 * required as it is reserved field_map value for nullable
	 * fields.
	 */
	if (!validate) {
		memset((char *)field_map - format->field_map_size, 0,
		       format->field_map_size);
	} else {
		memcpy((char *)field_map - format->field_map_size,
		       format->field_map_template, format->field_map_size);
	}

	struct region *region = &fiber()->gc;
	uint32_t mp_stack_size =
		format->max_path_tokens * sizeof(struct mp_frame);
	struct mp_frame *mp_stack = region_alloc(region, mp_stack_size);
	if (mp_stack == NULL) {
		diag_set(OutOfMemory, mp_stack_size, "region_alloc",
			 "mp_stack");
		return -1;
	}
	mp_stack[0].child_type = JSON_TOKEN_NUM;
	mp_stack[0].total = defined_field_count;
	mp_stack[0].curr = 0;
	uint32_t mp_stack_idx = 0;
	struct json_tree *tree = (struct json_tree *)&format->fields;
	struct json_token *parent = &tree->root;
	while (mp_stack[0].curr <= mp_stack[0].total) {
		/* Prepare key for tree lookup. */
		struct json_token token;
		if (mp_frame_parse(mp_stack, mp_stack_idx, &pos, &token) != 0)
			goto finish_frame;

		struct tuple_field *field =
			json_tree_lookup_entry(tree, parent, &token,
					       struct tuple_field, token);
		enum mp_type type = mp_typeof(*pos);
		if (field != NULL) {
			bool is_nullable = tuple_field_is_nullable(field);
			if (validate &&
			    !mp_type_is_compatible(type, field->type,
						   is_nullable) != 0) {
				const char *path =
					tuple_field_json_path(format, field,
							      region);
				if (path != NULL) {
					diag_set(ClientError, ER_FIELD_TYPE,
						 path,
						 field_type_strs[field->type]);
				}
				return -1;
			}
			if (field->offset_slot != TUPLE_OFFSET_SLOT_NIL) {
				field_map[field->offset_slot] =
					(uint32_t)(pos - tuple);
			}
		}
finish_frame:
		/* Prepare stack info for next iteration. */
		if (mp_frame_prepare(mp_stack, &mp_stack_idx,
				     format->max_path_tokens,
				     field != NULL ? &field->token : NULL,
				     &pos, &parent) != 0)
			goto end;
	};
end:
	return validate ? tuple_field_map_validate(format, field_map) : 0;
}

uint32_t
tuple_format_min_field_count(struct key_def * const *keys, uint16_t key_count,
			     const struct field_def *space_fields,
			     uint32_t space_field_count)
{
	uint32_t min_field_count = 0;
	for (uint32_t i = 0; i < space_field_count; ++i) {
		if (! space_fields[i].is_nullable)
			min_field_count = i + 1;
	}
	for (uint32_t i = 0; i < key_count; ++i) {
		const struct key_def *kd = keys[i];
		for (uint32_t j = 0; j < kd->part_count; ++j) {
			const struct key_part *kp = &kd->parts[j];
			if (!key_part_is_nullable(kp) &&
			    kp->fieldno + 1 > min_field_count)
				min_field_count = kp->fieldno + 1;
		}
	}
	return min_field_count;
}

/** Destroy tuple format subsystem and free resourses */
void
tuple_format_free()
{
	/* Clear recycled ids. */
	while (recycled_format_ids != FORMAT_ID_NIL) {
		uint16_t id = (uint16_t) recycled_format_ids;
		recycled_format_ids = (intptr_t) tuple_formats[id];
		tuple_formats[id] = NULL;
	}
	for (struct tuple_format **format = tuple_formats;
	     format < tuple_formats + formats_size; format++) {
		/* Do not unregister. Only free resources. */
		if (*format != NULL) {
			tuple_format_destroy(*format);
			free(*format);
		}
	}
	free(tuple_formats);
}

void
box_tuple_format_ref(box_tuple_format_t *format)
{
	tuple_format_ref(format);
}

void
box_tuple_format_unref(box_tuple_format_t *format)
{
	tuple_format_unref(format);
}

/**
 * Propagate @a field to MessagePack(field)[index].
 * @param[in][out] field Field to propagate.
 * @param index 0-based index to propagate to.
 *
 * @retval  0 Success, the index was found.
 * @retval -1 Not found.
 */
static inline int
tuple_field_go_to_index(const char **field, uint64_t index)
{
	enum mp_type type = mp_typeof(**field);
	if (type == MP_ARRAY) {
		uint32_t count = mp_decode_array(field);
		if (index >= count)
			return -1;
		for (; index > 0; --index)
			mp_next(field);
		return 0;
	} else if (type == MP_MAP) {
		index += TUPLE_INDEX_BASE;
		uint64_t count = mp_decode_map(field);
		for (; count > 0; --count) {
			type = mp_typeof(**field);
			if (type == MP_UINT) {
				uint64_t value = mp_decode_uint(field);
				if (value == index)
					return 0;
			} else if (type == MP_INT) {
				int64_t value = mp_decode_int(field);
				if (value >= 0 && (uint64_t)value == index)
					return 0;
			} else {
				/* Skip key. */
				mp_next(field);
			}
			/* Skip value. */
			mp_next(field);
		}
	}
	return -1;
}

/**
 * Propagate @a field to MessagePack(field)[key].
 * @param[in][out] field Field to propagate.
 * @param key Key to propagate to.
 * @param len Length of @a key.
 *
 * @retval  0 Success, the index was found.
 * @retval -1 Not found.
 */
static inline int
tuple_field_go_to_key(const char **field, const char *key, int len)
{
	enum mp_type type = mp_typeof(**field);
	if (type != MP_MAP)
		return -1;
	uint64_t count = mp_decode_map(field);
	for (; count > 0; --count) {
		type = mp_typeof(**field);
		if (type == MP_STR) {
			uint32_t value_len;
			const char *value = mp_decode_str(field, &value_len);
			if (value_len == (uint)len &&
			    memcmp(value, key, len) == 0)
				return 0;
		} else {
			/* Skip key. */
			mp_next(field);
		}
		/* Skip value. */
		mp_next(field);
	}
	return -1;
}

int
tuple_field_go_to_path(const char **data, const char *path, uint32_t path_len)
{
	int rc;
	struct json_lexer lexer;
	struct json_token token;
	json_lexer_create(&lexer, path, path_len, TUPLE_INDEX_BASE);
	while ((rc = json_lexer_next_token(&lexer, &token)) == 0) {
		switch (token.type) {
		case JSON_TOKEN_NUM:
			rc = tuple_field_go_to_index(data, token.num);
			break;
		case JSON_TOKEN_STR:
			rc = tuple_field_go_to_key(data, token.str, token.len);
			break;
		default:
			assert(token.type == JSON_TOKEN_END);
			return 0;
		}
		if (rc != 0) {
			*data = NULL;
			return 0;
		}
	}
	return rc;
}

int
tuple_field_raw_by_path(struct tuple_format *format, const char *tuple,
                        const uint32_t *field_map, const char *path,
                        uint32_t path_len, uint32_t path_hash,
                        const char **field)
{
	assert(path_len > 0);
	uint32_t fieldno;
	/*
	 * It is possible, that a field has a name as
	 * well-formatted JSON. For example 'a.b.c.d' or '[1]' can
	 * be field name. To save compatibility at first try to
	 * use the path as a field name.
	 */
	if (tuple_fieldno_by_name(format->dict, path, path_len, path_hash,
				  &fieldno) == 0) {
		*field = tuple_field_raw(format, tuple, field_map, fieldno);
		return 0;
	}
	struct json_lexer lexer;
	struct json_token token;
	json_lexer_create(&lexer, path, path_len, TUPLE_INDEX_BASE);
	int rc = json_lexer_next_token(&lexer, &token);
	if (rc != 0)
		goto error;
	switch(token.type) {
	case JSON_TOKEN_NUM: {
		fieldno = token.num;
		break;
	}
	case JSON_TOKEN_STR: {
		/* First part of a path is a field name. */
		uint32_t name_hash;
		if (path_len == (uint32_t) token.len) {
			name_hash = path_hash;
		} else {
			/*
			 * If a string is "field....", then its
			 * precalculated juajit hash can not be
			 * used. A tuple dictionary hashes only
			 * name, not path.
			 */
			name_hash = field_name_hash(token.str, token.len);
		}
		if (tuple_fieldno_by_name(format->dict, token.str, token.len,
					  name_hash, &fieldno) != 0)
			return 0;
		break;
	}
	default:
		assert(token.type == JSON_TOKEN_END);
		*field = NULL;
		return 0;
	}
	/* Optimize indexed JSON field data access. */
	struct key_part part;
	part.fieldno = fieldno;
	part.path = (char *)path + lexer.offset;
	part.path_len = path_len - lexer.offset;
	part.format_epoch = 0;
	rc = tuple_field_by_part_raw_slowpath(format, tuple, field_map, &part,
					      field);
	if (rc == 0)
		return 0;
	/* Setup absolute error position. */
	rc += lexer.offset;
error:
	assert(rc > 0);
	diag_set(ClientError, ER_ILLEGAL_PARAMS,
		 tt_sprintf("error in path on position %d", rc));
	return -1;
}

int
tuple_field_by_part_raw_slowpath(struct tuple_format *format, const char *data,
				 const uint32_t *field_map,
				 struct key_part *part, const char **raw)
{
	assert(part->path != NULL);
	struct tuple_field *field =
		tuple_format_field_by_path(format, part->fieldno, part->path,
					   part->path_len);
	if (field != NULL && field->offset_slot != TUPLE_OFFSET_SLOT_NIL) {
		int32_t offset_slot = field->offset_slot;
		assert(-offset_slot * sizeof(uint32_t) <=
		       format->field_map_size);

		/* Update format epoch cache. */
		assert(part->format_epoch != format->epoch);
		assert(format->epoch != 0);
		part->offset_slot_cache = offset_slot;
		part->format_epoch = format->epoch;

		*raw = field_map[offset_slot] == 0 ?
		       NULL : data + field_map[offset_slot];
		return 0;
	}
	/*
	 * Format doesn't have field representing specified part.
	 * Make slow tuple parsing.
	 */
	*raw = tuple_field_raw(format, data, field_map, part->fieldno);
	if (*raw == NULL)
		return 0;
	int rc = 0;
	if ((rc = tuple_field_go_to_path(raw, part->path, part->path_len)) != 0)
		return rc;
	return 0;
}
