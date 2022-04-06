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

local mp   = require "ccryptolib.internal.mp"
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

local ZERO = mp.num(0)

--- Reduces a number modulo q.
--
-- @tparam {number...} a A number a < 2q as 11 limbs in [0..2²⁵).
-- @treturn {number...} a mod q as 11 limbs in [0..2²⁴).
--
local function reduce(a)
    local c = mp.sub(a, Q)

    -- Return carry(a) if a < q.
    if mp.approx(c) < 0 then return mp.carry(a) end

    -- c >= q means c - q >= 0.
    -- Since q < 2²⁸⁸, c < 2q means c - q < q < 2²⁸⁸.
    -- c's limbs fit in (-2²⁶..2²⁶), since subtraction adds at most one bit.
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
    return reduce(mp.sub(Q, a))
end

--- Given two scalars a and b, computes 2⁻²⁶⁴ × a × b mod q.
--
-- @tparam {number...} a A number a as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A number b < q as 11 limbs in [0..2²⁴).
-- @treturn 2⁻²⁶⁴ × a × b mod q as 11 limbs in [0..2²⁴).
--
local function mul(a, b)
    local t0, t1 = mp.mul(a, b)
    local mq0, mq1 = mp.mul(mp.lmul(t0, T0), Q)
    local _, s1 = mp.dwadd(t0, t1, mq0, mq1)
    return reduce(s1)
end

--- Converts a scalar into Montgomery form.
--
-- @tparam {number...} a A number a as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function montgomery(a)
    -- 0 ≤ a < 2²⁶⁴ and 0 ≤ T1 < q.
    return mul(a, T1)
end

--- Converts a scalar from Montgomery form.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function demontgomery(a)
    -- It's REDC all over again except b is 1.
    local mq0, mq1 = mp.mul(mp.lmul(a, T0), Q)
    local _, s1 = mp.dwadd(a, ZERO, mq0, mq1)
    return reduce(s1)
end

--- Converts a Lua number to a scalar.
--
-- @tparam number n A number n in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × n mod q as 11 limbs in [0..2²⁴).
--
local function num(n)
    return montgomery({n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
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
