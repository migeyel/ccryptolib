--- Arithmetic on Curve25519's scalar field.
--
-- :::note Internal Module
-- This module is meant for internal use within the library. Its API is unstable
-- and subject to change without major version bumps.
-- :::
--
-- <br />
--
-- @module[kind=internal] internal.fq
--

local mp   = require "ccrytpolib.internal.mp"
local util = require "ccryptolib.internal.util"

local unpack = unpack or table.unpack

--- The scalar field's order, q.
local Q = {
    16110573,
    06494812,
    14047250,
    10680220,
    14612958,
    00000020,
    00000000,
    00000000,
    00000000,
    00000000,
    00004096,
}

--- The first Montgomery precomputed constant, -q⁻¹ mod 2²⁶⁴.
local T0 = {
    05537307,
    01942290,
    16765621,
    16628356,
    10618610,
    07072433,
    03735459,
    01369940,
    15276086,
    13038191,
    13409718,
}

--- The second Montgomery precomputed constant, 2⁵²⁸ mod q.
local T1 = {
    11711996,
    01747860,
    08326961,
    03814718,
    01859974,
    13327461,
    16105061,
    07590423,
    04050668,
    08138906,
    00000283,
}

--- Reduces a number modulo q.
--
-- @tparam {number...} a A number a < 2q as 12 limbs in [0..2²⁴).
-- @treturn {number...} a mod q as 11 limbs in [0..2²⁴).
--
local function reduce(a)
    local c = {unpack(a, 1, 11)} -- a < 2q implies that a[12] = 0.

    -- Return c if c < r.
    for i = 11, 1, -1 do
        if c[i] < Q[i] then
            return c
        elseif c[i] > Q[i] then
            break
        end
    end

    for i = 1, 11 do
        c[i] = c[i] - Q[i]
    end

    -- c >= q means c - q >= 0.
    -- Since q < 2²⁸⁸, c < 2q means c - q < q < 2²⁸⁸ = 2^(24 × (11 + 1)).
    -- c's limbs fit in [-2²⁵..2²⁵], since subtraction adds at most one bit.
    local cc = mp.carry(c)
    cc[12] = nil -- cc < q implies that cc[12] = 0.
    return cc
end

--- Adds two scalars mod q.
--
-- If the two operands are in Montgomery form, returns the correct result also
-- in Montgomery form, since (2²⁶⁴ × a) + (2²⁶⁴ × b) ≡ 2²⁶⁴ × (a + b) (mod q).
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A number b < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} a + b mod q as 11 limbs in [0..2²⁴).
--
local function add(a, b)
    return reduce(mp.add(a, b))
end

--- Negates a scalar mod q.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} -a mod q as 11 limbs in [0..2²⁴).
--
local function neg(a)
    local c = {}
    for i = 1, 11 do
        c[i] = Q[i] - a[i]
    end

    -- 0 < c < q implies 0 < q - c < q < 2²⁸⁸ = 2^(24 × (11 + 1)).
    -- c's limbs fit in [-2²⁵..2²⁵], since subtraction adds at most one bit.
    -- q - c < q also implies q - c < 2q.
    return reduce(mp.carry(c))
end

--- Given a scalar a, computes 2⁻²⁶⁴ a mod q.
--
-- @tparam {number...} a A number a < 2²⁶⁴ × q as 22 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function redc(a)
    local al = {unpack(a, 1, 11)}
    local mm = mp.mul(al, T0)
    local m = {unpack(mm, 1, 11)}
    local mr = mp.mul(m, Q)
    local t = mp.add(a, mr)
    return reduce({unpack(t, 12, 23)})
end

--- Converts a scalar into Montgomery form.
--
-- @tparam {number...} a A number a as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function montgomery(a)
    -- a < 2²⁶⁴ and T1 < q imply that a × T1 < 2²⁶⁴ × q.
    return redc(mp.mul(a, T1))
end

--- Converts a scalar from Montgomery form.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function demontgomery(a)
    a = {unpack(a)}
    for i = 12, 22 do a[i] = 0 end
    -- a < q < 2²⁶⁴ × q.
    return redc(a)
end

--- Converts a Lua number to a scalar.
--
-- @tparam number n A number n in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × n mod q as 11 limbs in [0..2²⁴).
--
local function num(n)
    return montgomery({n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
end

--- Multiplies two scalars mod q.
--
-- @tparam {number...} a 2²⁶⁴ × a' mod q as 11 limbs in [0..2²⁴).
-- @tparam {number...} b 2²⁶⁴ × b' mod q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × a' × b' mod q as 11 limbs in [0..2²⁴).
--
local function mul(a, b)
    -- {a, b} < q so a × b < q² < 2²⁶⁴ × q.
    return redc(mp.mul(a, b))
end

--- Encodes a scalar.
--
-- @tparam {number...} a A number 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
-- @treturn string The 32-byte string encoding of a.
--
local function encode(a)
    return ("<I3I3I3I3I3I3I3I3I3I3I2"):pack(unpack(demontgomery(a)))
end

--- Decodes a scalar.
--
-- @tparam string str A 32-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function decode(str)
    local dec = {("<I3I3I3I3I3I3I3I3I3I3I2"):unpack(str)} dec[12] = nil
    return montgomery(dec)
end

--- Decodes a scalar from a "wide" string.
--
-- @tparam string str A 64-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function decodeWide(str)
    local low = {("<I3I3I3I3I3I3I3I3I3I3I3"):unpack(str)} low[12] = nil
    local high = {("<I3I3I3I3I3I3I3I3I3I3I1"):unpack(str, 34)} high[12] = nil
    return add(montgomery(low), montgomery(montgomery(high)))
end

--- Decodes a scalar using the X25519/Ed25519 bit clamping scheme.
--
-- @tparam string str A 32-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × clamp(a) mod q as 11 limbs in [0..2²⁴).
--
local function decodeClamped(str)
    -- Decode.
    local words = {("<I3I3I3I3I3I3I3I3I3I3I2"):unpack(str)} words[12] = nil

    -- Clamp.
    words[1] = bit32.band(words[1], 0xfffff8)
    words[11] = bit32.band(words[11], 0x7fff)
    words[11] = bit32.bor(words[11], 0x4000)

    return montgomery(words)
end

--- Returns a scalar in binary.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 265 bits.
--
local function bits(a)
    return util.rebaseLE(demontgomery(a), 2 ^ 24, 2)
end

--- Clones a scalar.
--
-- @tparam {number...} a The scalar to clone.
-- @treturn {number...} The exact same value but as a different object.
--
local function clone(a)
    return {unpack(a)}
end

return {
    num = num,
    add = add,
    neg = neg,
    montgomery = montgomery,
    demontgomery = demontgomery,
    mul = mul,
    encode = encode,
    decode = decode,
    decodeWide = decodeWide,
    decodeClamped = decodeClamped,
    bits = bits,
    clone = clone,
}
