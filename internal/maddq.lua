--- Additive arithmetic masking modulo q  (unstable, for internal use only).
--
-- Representing secret scalars in Cobalt is potentially dangerous since the VM
-- leaks information through timing. To remedy this, we use _masking_, which is
-- a randomized representation of a scalar s as several values {s₁, s₂, s₃, ...}
-- such that s₁ + s₂ + s₃ + ... ≡ s (mod q).
--
-- Using masking, we can perform arithmetic on the masked value without needing
-- to render the raw secrets in memory. After these operations, we can unwrap
-- the result which, depending on the operations, is harder to measure.
--
-- @module internal.maddq
--

local fq     = require "ccryptolib.internal.fq"
local random = require "ccryptolib.random"

--- Builds a masked scalar from a regular one.
--
-- @tparam {number...} val The input scalar.
-- @tparam number order How many values to use, must be at least 2.
-- @treturn {{number...}...} The masked scalar.
--
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

--- Unwraps a masked scalar, getting the raw unmasked value.
--
-- @tparam {{number...}...} arr The input masked scalar.
-- @treturn {number...} The unmasked scalar.
--
local function unwrap(arr)
    local sum = fq.num(0)
    for i = 1, #arr do sum = fq.add(sum, arr[i]) end
    return sum
end

--- Encodes a masked scalar into a string.
--
-- @tparam {{number...}...} arr The input masked scalar.
-- @treturn string The encoded value.
--
local function encode(arr)
    local out = {}
    for i = 1, #arr do out[i] = fq.encode(arr[i]) end
    return table.concat(out)
end

--- Decodes a masked scalar from a string.
--
-- @tparam string str The encoded scalar. Length must be a multiple of 32.
-- @treturn {{number...}...} The decoded value.
--
local function decode(str)
    local out = {}
    for i = 1, #str / 32 do out[i] = fq.decode(str:sub(i * 32 - 31, i * 32)) end
    return out
end

--- Rerandomizes a masked scalar's representation.
--
-- @tparam {{number...}...} arr The input masked scalar.
-- @treturn {{number...}...} The rerandomized representation of the input.
--
local function remask(arr)
    local out = new(fq.num(0), #arr)
    for i = 1, #arr do out[i] = fq.add(out[i], arr[i]) end
    return out
end

--- Multiplies a masked scalar by a regular scalar.
--
-- @tparam {{number...}...} arr The input masked scalar.
-- @tparam {number...} k The scalar to multiply by.
-- @treturn {{number...}...} The masked product of both values.
--
local function mul(arr, k)
    local out = {}
    for i = 1, #arr do out[i] = fq.mul(arr[i], k) end
    return out
end

--- Adds a regular scalar to a masked scalar.
--
-- @tparam {{number...}...} The input masked scalar.
-- @tparam {number...} v The scalar to add to.
-- @treturn {{number...}...} The masked sum of both values.
--
local function add(arr, v)
    local out = {}
    for i = 1, #arr do out[i] = fq.clone(arr[i]) end
    out[#arr] = fq.add(out[#arr], v)
    return out
end

return {
    new = new,
    unwrap = unwrap,
    encode = encode,
    decode = decode,
    remask = remask,
    mul = mul,
    add = add,
}
