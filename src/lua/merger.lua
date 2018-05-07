local ffi = require('ffi')
local merger = require('merger')

local merger_t = ffi.typeof('struct merger')

local methods = {
    ['select'] = merger.internal.select,
    ['pairs']  = merger.internal.ipairs,
    ['ipairs']  = merger.internal.ipairs,
}

ffi.metatype(merger_t, {
    __index = function(self, key)
        return methods[key]
    end,
    -- Lua 5.2 compatibility
    __pairs = merger.internal.ipairs,
    __ipairs = merger.internal.ipairs,
})
