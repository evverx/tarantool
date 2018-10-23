function swim_info_sorted()
    local t = swim.info()
    local keys = {}
    for k, _ in pairs(t) do table.insert(keys, k) end
    table.sort(keys)
    local res = {}
    for _, k in pairs(keys) do table.insert(res, {k, t[k]}) end
    return setmetatable(res, {__index = t})
end
