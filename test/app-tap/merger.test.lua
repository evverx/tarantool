#!/usr/bin/env tarantool

local tap = require('tap')
local buffer = require('buffer')
local msgpackffi = require('msgpackffi')
local digest = require('digest')
local merger = require('merger')
local crypto = require('crypto')
local fiber = require('fiber')
local utf8 = require('utf8')
local ffi = require('ffi')

local IPROTO_DATA = 48

local function merger_usage(param)
    local msg = 'merger_inst:{ipairs,pairs,select}(' ..
        '{source, source, ...}[, {' ..
        'descending = <boolean> or <nil>, ' ..
        'decode = \'raw\' / \'select\' / \'call\' / \'chain\' / <nil>, ' ..
        'buffer = <cdata<struct ibuf>> or <nil>, ' ..
        'encode = \'raw\' / \'select\' / \'call\' / \'chain\' / <nil>, ' ..
        'encode_chain_len = <number> or <nil>}])'
    if not param then
        return ('Bad params, use: %s'):format(msg)
    else
        return ('Bad param "%s", use: %s'):format(param, msg)
    end
end

-- Get buffer with data encoded without last 'trunc' bytes.
local function truncated_msgpack_buffer(data, trunc)
    local data = msgpackffi.encode(data)
    data = data:sub(1, data:len() - trunc)
    local len = data:len()
    local buf = buffer.ibuf()
    -- Ensure we have enough buffer to write len + trunc bytes.
    buf:reserve(len + trunc)
    local p = buf:alloc(len)
    -- Ensure len bytes follows with trunc zero bytes.
    ffi.copy(p, data .. string.rep('\0', trunc), len + trunc)
    return buf
end

local bad_merger_new_calls = {
    -- Cases to call before box.cfg{}.
    {
        'Pass a field on an unknown type',
        parts = {{
            fieldno = 2,
            type = 'unknown',
        }},
        exp_err = 'Unknown field type: unknown',
    },
    {
        'Try to use collation_id before box.cfg{}',
        parts = {{
            fieldno = 1,
            type = 'string',
            collation_id = 2,
        }},
        exp_err = 'Cannot use collations: please call box.cfg{}',
    },
    {
        'Try to use collation before box.cfg{}',
        parts = {{
            fieldno = 1,
            type = 'string',
            collation = 'unicode_ci',
        }},
        exp_err = 'Cannot use collations: please call box.cfg{}',
    },
    function()
        -- For collations.
        box.cfg{}
    end,
    -- Cases to call after box.cfg{}.
    {
        'Try to use both collation_id and collation',
        parts = {{
            fieldno = 1,
            type = 'string',
            collation_id = 2,
            collation = 'unicode_ci',
        }},
        exp_err = 'Conflicting options: collation_id and collation',
    },
    {
        'Unknown collation_id',
        parts = {{
            fieldno = 1,
            type = 'string',
            collation_id = 42,
        }},
        exp_err = 'Unknown collation_id: 42',
    },
    {
        'Unknown collation name',
        parts = {{
            fieldno = 1,
            type = 'string',
            collation = 'unknown',
        }},
        exp_err = 'Unknown collation: "unknown"',
    },
}

local bad_merger_methods_calls = {
    {
        'Bad opts',
        sources = {},
        opts = 1,
        exp_err = merger_usage(nil),
    },
    {
        'Bad opts.descending',
        sources = {},
        opts = {descending = 1},
        exp_err = merger_usage('descending'),
    },
    {
        'Bad opts.decode',
        sources = {},
        opts = {decode = 1},
        exp_err = merger_usage('decode'),
    },
    {
        'Bad source',
        sources = {1},
        opts = nil,
        exp_err = 'Unknown source type at index 1',
    },
    {
        'Bad cdata source',
        sources = {ffi.new('char *')},
        opts = nil,
        exp_err = 'Unknown source type at index 1',
    },
    {
        'Missed encode_chain_len',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode = 'chain'},
        exp_err = '"encode_chain_len" is mandatory when "buffer" and ' ..
            '{encode = \'chain\'} are used',
    },
    {
        'Wrong source of table type',
        sources = {{1}},
        opts = nil,
        exp_err = 'A tuple or a table expected, got number',
    },
    {
        'Use buffer with an iterator result',
        sources = {},
        opts = {buffer = buffer.ibuf()},
        funcs = {'pairs', 'ipairs'},
        exp_err = '"buffer" option is forbidden with merger_inst:pairs(<...>)',
    },
    {
        'Bad decode type',
        sources = {},
        opts = {decode = 1},
        exp_err = merger_usage('decode'),
    },
    {
        'Bad decode string',
        sources = {},
        opts = {decode = 'bad value'},
        exp_err = merger_usage('decode'),
    },
    {
        'A table source ignores {decode = \'chain\'}',
        sources = {{{''}}},
        opts = {decode = 'chain'},
        exp_err = nil,
    },
    {
        'An iterator source ignores {decode = \'chain\'}',
        sources = {{pairs({})}},
        opts = {decode = 'chain'},
        exp_err = nil,
    },
    {
        'Bad encode type',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode = 1},
        funcs = {'select'},
        exp_err = merger_usage('encode'),
    },
    {
        'Bad encode string',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode = 'bad value'},
        funcs = {'select'},
        exp_err = merger_usage('encode'),
    },
    {
        -- Any encode value should lead to an error, but we check
        -- only 'select' here.
        'Use "encode" without "buffer"',
        sources = {},
        opts = {encode = 'select'},
        exp_err = '"buffer" option is mandatory when "encode" is used',
    },
    {
        'Use "encode_chain_len" without "encode"',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode_chain_len = 1},
        exp_err = '"encode_chain_len" is forbidden without ' ..
            '{encode = \'chain\'}',
    },
    {
        -- Any encode value except "chain" should lead to an
        -- error, but we check only 'select' here.
        'Use "encode_chain_len" with "encode" != "chain"',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode = 'select',
            encode_chain_len = 1},
        exp_err = '"encode_chain_len" is forbidden without ' ..
            '{encode = \'chain\'}',
    },
    {
        'Bad encode_chain_len type',
        sources = {},
        opts = {buffer = buffer.ibuf(), encode = 'chain',
            encode_chain_len = 'bad value'},
        exp_err = merger_usage('encode_chain_len'),
    },
    {
        'Bad msgpack source: wrong length of the tuples array',
        -- Remove the last tuple from msgpack data, but keep old
        -- tuples array size.
        sources = {
            truncated_msgpack_buffer({[IPROTO_DATA] = {{''}, {''}, {''}}}, 2),
        },
        opts = {},
        funcs = {'select'},
        exp_err = 'Unexpected msgpack buffer end',
    },
    {
        'Bad msgpack source: wrong length of a tuple',
        -- Remove half of the last tuple, but keep old tuple size.
        sources = {
            truncated_msgpack_buffer({[IPROTO_DATA] = {{''}, {''}, {''}}}, 1),
        },
        opts = {},
        funcs = {'select'},
        exp_err = 'Unexpected msgpack buffer end',
    },
}

local schemas = {
    {
        name = 'small_unsigned',
        parts = {
            {
                fieldno = 2,
                type = 'unsigned',
            }
        },
        gen_tuple = function(tupleno)
            return {'id_' .. tostring(tupleno), tupleno}
        end,
    },
    -- Merger allocates a memory for 8 parts by default.
    -- Test that reallocation works properly.
    -- Test with N-1 equal parts and Nth different.
    {
        name = 'many_parts',
        parts = (function()
            local parts = {}
            for i = 1, 128 do
                parts[i] = {
                    fieldno = i,
                    type = 'unsigned',
                }
            end
            return parts
        end)(),
        gen_tuple = function(tupleno)
            local tuple = {}
            -- 127 constant parts
            for i = 1, 127 do
                tuple[i] = i
            end
            -- 128th part is varying
            tuple[128] = tupleno
            return tuple
        end,
        -- reduce tuples count to decrease test run time
        tuples_cnt = 16,
    },
    -- Test null value in nullable field of an index.
    {
        name = 'nullable',
        parts = {
            {
                fieldno = 1,
                type = 'unsigned',
            },
            {
                fieldno = 2,
                type = 'string',
                is_nullable = true,
            },
        },
        gen_tuple = function(i)
            if i % 1 == 1 then
                return {0, tostring(i)}
            else
                return {0, box.NULL}
            end
        end,
    },
    -- Test index part with 'collation_id' option (as in net.box's
    -- response).
    {
        name = 'collation_id',
        parts = {
            {
                fieldno = 1,
                type = 'string',
                collation_id = 2, -- unicode_ci
            },
        },
        gen_tuple = function(i)
            local letters = {'a', 'b', 'c', 'A', 'B', 'C'}
            if i <= #letters then
                return {letters[i]}
            else
                return {''}
            end
        end,
    },
    -- Test index part with 'collation' option (as in local index
    -- parts).
    {
        name = 'collation',
        parts = {
            {
                fieldno = 1,
                type = 'string',
                collation = 'unicode_ci',
            },
        },
        gen_tuple = function(i)
            local letters = {'a', 'b', 'c', 'A', 'B', 'C'}
            if i <= #letters then
                return {letters[i]}
            else
                return {''}
            end
        end,
    },
}

local function is_unicode_ci_part(part)
    return part.collation_id == 2 or part.collation == 'unicode_ci'
end

local function sort_tuples(tuples, parts, opts)
    local function tuple_comparator(a, b)
        for _, part in ipairs(parts) do
            local fieldno = part.fieldno
            if a[fieldno] ~= b[fieldno] then
                if a[fieldno] == nil then
                    return -1
                end
                if b[fieldno] == nil then
                    return 1
                end
                if is_unicode_ci_part(part) then
                    return utf8.casecmp(a[fieldno], b[fieldno])
                end
                return a[fieldno] < b[fieldno] and -1 or 1
            end
        end

        return 0
    end

    local function tuple_comparator_wrapper(a, b)
        local cmp = tuple_comparator(a, b)
        if cmp < 0 then
            return not opts.descending
        elseif cmp > 0 then
            return opts.descending
        else
            return false
        end
    end

    table.sort(tuples, tuple_comparator_wrapper)
end

local function lowercase_unicode_ci_fields(tuples, parts)
    for i = 1, #tuples do
        local tuple = tuples[i]
        for _, part in ipairs(parts) do
            if is_unicode_ci_part(part) then
                -- Workaround #3709.
                if tuple[part.fieldno]:len() > 0 then
                    tuple[part.fieldno] = utf8.lower(tuple[part.fieldno])
                end
            end
        end
    end
end

local function prepare_data(schema, tuples_cnt, sources_cnt, opts)
    local opts = opts or {}
    local input_type = opts.input_type
    local use_table_as_tuple = opts.use_table_as_tuple

    local tuples = {}
    local exp_result = {}

    -- Ensure empty sources are empty table and not nil.
    for i = 1, sources_cnt do
        if tuples[i] == nil then
            tuples[i] = {}
        end
    end

    -- Prepare N tables with tuples as input for merger.
    for i = 1, tuples_cnt do
        -- [1, sources_cnt]
        local guava = digest.guava(i, sources_cnt) + 1
        local tuple = schema.gen_tuple(i)
        table.insert(exp_result, tuple)
        if not use_table_as_tuple then
            assert(input_type ~= 'buffer')
            tuple = box.tuple.new(tuple)
        end
        table.insert(tuples[guava], tuple)
    end

    -- Sort tuples within each source.
    for _, source_tuples in pairs(tuples) do
        sort_tuples(source_tuples, schema.parts, opts)
    end

    -- Sort expected result.
    sort_tuples(exp_result, schema.parts, opts)

    -- Fill sources.
    local sources
    if input_type == 'table' then
        -- Imitate netbox's select w/o {buffer = ...}.
        sources = tuples
    elseif input_type == 'buffer' then
        -- Imitate netbox's select with {buffer = ...}.
        sources = {}
        for i = 1, sources_cnt do
            local data
            if opts.decode == 'raw' then
                data = tuples[i]
            elseif opts.decode == nil or opts.decode == 'select' then
                data = {[IPROTO_DATA] = tuples[i]}
            elseif opts.decode == 'call' then
                data = {[IPROTO_DATA] = {tuples[i]}}
            elseif opts.decode == 'chain' then
                data = {[IPROTO_DATA] = {{tuples[i]}}}
            else
                assert(false)
            end
            sources[i] = buffer.ibuf()
            msgpackffi.internal.encode_r(sources[i], data, 0)
        end
    elseif input_type == 'iterator' then
        -- Lua iterator.
        sources = {}
        for i = 1, sources_cnt do
            sources[i] = {
                -- gen (next)
                next,
                -- param (tuples)
                tuples[i],
                -- state (idx)
                nil
            }
        end
    end

    return sources, exp_result
end

local function test_case_opts_str(opts)
    local params = {}

    if opts.decode then
        table.insert(params, 'decode: ' .. opts.decode)
    end

    if opts.encode then
        table.insert(params, 'encode: ' .. opts.encode)
    end

    if opts.input_type then
        table.insert(params, 'input_type: ' .. opts.input_type)
    end

    if opts.output_type then
        table.insert(params, 'output_type: ' .. opts.output_type)
    end

    if opts.descending then
        table.insert(params, 'descending')
    end

    if opts.use_table_as_tuple then
        table.insert(params, 'use_table_as_tuple')
    end

    if next(params) == nil then
        return ''
    end

    return (' (%s)'):format(table.concat(params, ', '))
end

local function run_merger(test, schema, tuples_cnt, sources_cnt, opts)
    fiber.yield()

    local opts = opts or {}

    -- Prepare data.
    local sources, exp_result =
        prepare_data(schema, tuples_cnt, sources_cnt, opts)

    -- Create a merger instance and fill options.
    local merger_inst = merger.new(schema.parts)
    local merger_opts = {
        decode = opts.decode,
        encode = opts.encode,
        descending = opts.descending,
    }
    if opts.output_type == 'buffer' then
        merger_opts.buffer = buffer.ibuf()
    end
    if opts.encode == 'chain' then
        merger_opts.encode_chain_len = 1
    end

    local res

    -- Run merger and prepare output for compare.
    if opts.output_type == 'table' then
        -- Table output.
        res = merger_inst:select(sources, merger_opts)
    elseif opts.output_type == 'buffer' then
        -- Buffer output.
        merger_inst:select(sources, merger_opts)
        local obuf = merger_opts.buffer
        local data = msgpackffi.decode(obuf.rpos)

        if opts.encode == 'raw' then
            res = data
        elseif opts.encode == nil or opts.encode == 'select' then
            res = data[IPROTO_DATA]
        elseif opts.encode == 'call' then
            res = data[IPROTO_DATA][1]
        elseif opts.encode == 'chain' then
            res = data[IPROTO_DATA][1][1]
        else
            assert(false)
        end
    else
        -- Iterator output.
        assert(opts.output_type == 'iterator')
        res = merger_inst:pairs(sources, merger_opts):totable()
    end

    -- A bit more postprocessing to compare.
    for i = 1, #res do
        if type(res[i]) ~= 'table' then
            res[i] = res[i]:totable()
        end
    end

    -- unicode_ci does not differentiate btw 'A' and 'a', so the
    -- order is arbitrary. We transform fields with unicode_ci
    -- collation in parts to lower case before comparing.
    lowercase_unicode_ci_fields(res, schema.parts)
    lowercase_unicode_ci_fields(exp_result, schema.parts)

    test:is_deeply(res, exp_result,
        ('check order on %3d tuples in %4d sources%s')
        :format(tuples_cnt, sources_cnt, test_case_opts_str(opts)))
end

local function run_case(test, schema, opts)
    local opts = opts or {}

    local case_name = ('testing on schema %s%s'):format(
        schema.name, test_case_opts_str(opts))
    local tuples_cnt = schema.tuples_cnt or 100

    local encode = opts.encode
    local decode = opts.decode
    local input_type = opts.input_type
    local output_type = opts.output_type
    local use_table_as_tuple = opts.use_table_as_tuple

    -- Skip meaningless flags combinations.
    if input_type ~= 'buffer' and decode ~= nil then
        return
    end
    if output_type ~= 'buffer' and encode ~= nil then
        return
    end
    if input_type == 'buffer' and not use_table_as_tuple then
        return
    end

    test:test(case_name, function(test)
        test:plan(6)

        -- Check with small buffers count.
        run_merger(test, schema, tuples_cnt, 1, opts)
        run_merger(test, schema, tuples_cnt, 2, opts)
        run_merger(test, schema, tuples_cnt, 3, opts)
        run_merger(test, schema, tuples_cnt, 4, opts)
        run_merger(test, schema, tuples_cnt, 5, opts)

        -- Check more buffers then tuples count.
        run_merger(test, schema, tuples_cnt, 1000, opts)
    end)
end

local test = tap.test('merger')
test:plan(#bad_merger_new_calls - 1 + #bad_merger_methods_calls +
    #schemas * 126)

-- Bad merger.new() calls.
for _, case in ipairs(bad_merger_new_calls) do
    if type(case) == 'function' then
        case()
    else
        local ok, err = pcall(merger.new, case.parts)
        test:is_deeply({ok, err}, {false, case.exp_err}, case[1])
    end
end

-- Create the instance to use in testing merger's methods below.
local merger_inst = merger.new({{
    fieldno = 1,
    type = 'string',
}})

-- Bad source or/and opts parameters for merger's methods.
for _, case in ipairs(bad_merger_methods_calls) do
    test:test(case[1], function(test)
        local funcs = case.funcs or {'pairs', 'ipairs', 'select'}
        test:plan(#funcs)
        for _, func in ipairs(funcs) do
            local exp_ok = case.exp_err == nil
            local ok, err = pcall(merger_inst[func], merger_inst, case.sources,
                case.opts)
            if ok then
                err = nil
            end
            test:is_deeply({ok, err}, {exp_ok, case.exp_err}, func)
        end
    end)
end

-- Merging cases.
for _, decode in ipairs({'nil', 'raw', 'select', 'call', 'chain'}) do
    for _, encode in ipairs({'nil', 'raw', 'select', 'call', 'chain'}) do
        for _, input_type in ipairs({'buffer', 'table', 'iterator'}) do
            for _, output_type in ipairs({'buffer', 'table', 'iterator'}) do
                for _, descending in ipairs({false, true}) do
                    for _, use_table_as_tuple in ipairs({false, true}) do
                        for _, schema in ipairs(schemas) do
                            decode = decode ~= 'nil' and decode or nil
                            encode = encode ~= 'nil' and encode or nil
                            run_case(test, schema, {
                                decode = decode,
                                encode = encode,
                                input_type = input_type,
                                output_type = output_type,
                                descending = descending,
                                use_table_as_tuple = use_table_as_tuple,
                            })
                        end
                    end
                end
            end
        end
    end
end

os.exit(test:check() and 0 or 1)
