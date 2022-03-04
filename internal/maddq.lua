local fq     = require "ccryptolib.internal.fq"
local random = require "ccryptolib.random"

local function new(val, order)
    local out = {}
    local sum = fq.num(0)
    for i = 1, order - 1 do
        out[i] = fq.decodeWide(random.random(64))
        sum = fq.add(sum, out[i])
    end

    out[order] = fq.add(val, fq.neg(sum))

    return out
end

local function encode(arr)
    local out = {}
    for i = 1, #arr do out[i] = fq.encode(arr[i]) end
    return table.concat(out)
end

local function decode(str)
    local out = {}
    for i = 1, #str / 32 do out[i] = fq.decode(str:sub(i * 32 - 31, i * 32)) end
    return out
end

local function remask(arr)
    local out = new(fq.num(0), #arr)
    for i = 1, #arr do out[i] = fq.add(out[i], arr[i]) end
    return out
end

local function reduce(arr, k)
    local out = fq.num(0)
    for i = 1, #arr do out = fq.add(out, fq.mul(arr[i], k)) end
    return out
end

local function add(arr, v)
    local out = {}
    for i = 1, #arr do out[i] = fq.clone(arr[i]) end
    out[#arr] = fq.add(out[#arr], v)
    return out
end

return {
    new = new,
    encode = encode,
    decode = decode,
    remask = remask,
    reduce = reduce,
    add = add,
}
