--- Multi-precision arithmetic on 264-bit integers.
--
-- :::note Internal Module
-- This module is meant for internal use within the library. Its API is unstable
-- and subject to change without major version bumps.
-- :::
--
-- <br />
--
-- @module[kind=internal] internal.mp
--

local unpack = unpack or table.unpack

--- Carries a number in base 2²⁴ into a signed limb form.
--
-- @tparam {number...} a A number a in (-2²⁸⁸..2²⁸⁸) as 11 limbs in
-- [-2⁵²..2⁵²].
-- @treturn {number...} a as 12 limbs in (-2²⁴..2²⁴).
--
local function carryWeak(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)

    local h00 = a00 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a01 = a01 + h00 * 2 ^ -24
    local h01 = a01 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a02 = a02 + h01 * 2 ^ -24
    local h02 = a02 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a03 = a03 + h02 * 2 ^ -24
    local h03 = a03 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a04 = a04 + h03 * 2 ^ -24
    local h04 = a04 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a05 = a05 + h04 * 2 ^ -24
    local h05 = a05 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a06 = a06 + h05 * 2 ^ -24
    local h06 = a06 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a07 = a07 + h06 * 2 ^ -24
    local h07 = a07 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a08 = a08 + h07 * 2 ^ -24
    local h08 = a08 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a09 = a09 + h08 * 2 ^ -24
    local h09 = a09 + 3 * 2 ^ 75 - 3 * 2 ^ 75 a10 = a10 + h09 * 2 ^ -24
    local h10 = a10 + 3 * 2 ^ 75 - 3 * 2 ^ 75

    return {
        a00 - h00,
        a01 - h01,
        a02 - h02,
        a03 - h03,
        a04 - h04,
        a05 - h05,
        a06 - h06,
        a07 - h07,
        a08 - h08,
        a09 - h09,
        a10 - h10,
        h10 * 2 ^ -24,
    }
end

--- Carries a number in base 2²⁴.
--
-- @tparam {number...} a A number a in [0..2²⁸⁸) as 11 limbs in
-- [-2⁵²..2⁵²].
-- @treturn {number...} a as 12 limbs in [0..2²⁴).
--
local function carry(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)

    local l00 = a00 % 2 ^ 24 a01 = a01 + (a00 - l00) * 2 ^ -24
    local l01 = a01 % 2 ^ 24 a02 = a02 + (a01 - l01) * 2 ^ -24
    local l02 = a02 % 2 ^ 24 a03 = a03 + (a02 - l02) * 2 ^ -24
    local l03 = a03 % 2 ^ 24 a04 = a04 + (a03 - l03) * 2 ^ -24
    local l04 = a04 % 2 ^ 24 a05 = a05 + (a04 - l04) * 2 ^ -24
    local l05 = a05 % 2 ^ 24 a06 = a06 + (a05 - l05) * 2 ^ -24
    local l06 = a06 % 2 ^ 24 a07 = a07 + (a06 - l06) * 2 ^ -24
    local l07 = a07 % 2 ^ 24 a08 = a08 + (a07 - l07) * 2 ^ -24
    local l08 = a08 % 2 ^ 24 a09 = a09 + (a08 - l08) * 2 ^ -24
    local l09 = a09 % 2 ^ 24 a10 = a10 + (a09 - l09) * 2 ^ -24
    local l10 = a10 % 2 ^ 24
    local h10 = (a10 - l10) * 2 ^ -24

    return {l00, l01, l02, l03, l04, l05, l06, l07, l08, l09, l10, h10}
end

--- Adds two numbers.
--
-- @tparam {number...} a An array of 11 limbs in (k..l).
-- @tparam {number...} b An array of 11 limbs in (m..n).
-- @treturn {number...} a + b as 11 limbs in ((k + m)..(l + n)).
--
local function add(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10 = unpack(b)

    return {
        a00 + b00,
        a01 + b01,
        a02 + b02,
        a03 + b03,
        a04 + b04,
        a05 + b05,
        a06 + b06,
        a07 + b07,
        a08 + b08,
        a09 + b09,
        a10 + b10,
    }
end

--- Subtracts a number from another.
--
-- @tparam {number...} a An array of 11 limbs in (k..l).
-- @tparam {number...} b An array of 11 limbs in (m..n).
-- @treturn {number...} a + b as 11 limbs in ((k - m)..(l - n)).
--
local function sub(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10 = unpack(b)

    return {
        a00 - b00,
        a01 - b01,
        a02 - b02,
        a03 - b03,
        a04 - b04,
        a05 - b05,
        a06 - b06,
        a07 - b07,
        a08 - b08,
        a09 - b09,
        a10 - b10,
    }
end

--- Computes the lower half of a product between two numbers.
--
-- @tparam {number...} a A nonnegative integer as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A nonnegative integer as 11 limbs in [0..2²⁴).
-- @treturn {number...} c ≡ a × b (mod 2²⁶⁴) as 11 limbs in [0..2²⁴).
-- @treturn number ⌊a × b ÷ 2²⁶⁴⌋.
--
local function lmul(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10 = unpack(b)

    local out = carry {
        a00 * b00,
        a01 * b00 + a00 * b01,
        a02 * b00 + a01 * b01 + a00 * b02,
        a03 * b00 + a02 * b01 + a01 * b02 + a00 * b03,
        a04 * b00 + a03 * b01 + a02 * b02 + a01 * b03 + a00 * b04,
        a05 * b00 + a04 * b01 + a03 * b02 + a02 * b03 + a01 * b04 + a00 * b05,
        a06 * b00 + a05 * b01 + a04 * b02 + a03 * b03 + a02 * b04 + a01 * b05 + a00 * b06,
        a07 * b00 + a06 * b01 + a05 * b02 + a04 * b03 + a03 * b04 + a02 * b05 + a01 * b06 + a00 * b07,
        a08 * b00 + a07 * b01 + a06 * b02 + a05 * b03 + a04 * b04 + a03 * b05 + a02 * b06 + a01 * b07 + a00 * b08,
        a09 * b00 + a08 * b01 + a07 * b02 + a06 * b03 + a05 * b04 + a04 * b05 + a03 * b06 + a02 * b07 + a01 * b08 + a00 * b09,
        a10 * b00 + a09 * b01 + a08 * b02 + a07 * b03 + a06 * b04 + a05 * b05 + a04 * b06 + a03 * b07 + a02 * b08 + a01 * b09 + a00 * b10,
    }

    -- Strip overflow.
    local of = out[12]
    out[12] = nil

    return out, of
end

--- Computes the a product between two numbers.
--
-- @tparam {number...} a An array of 11 limbs in [0..2²⁴).
-- @tparam {number...} b An array of 11 limbs in [0..2²⁴).
-- @treturn {number...} The first 11 limbs of a × b in [0..2²⁴).
-- @treturn {number...} The last 11 limbs of a × b in [0..2²⁴).
--
local function mul(a, b)
    local low, of = lmul(a, b)

    local _, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    local _, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10 = unpack(b)

    local high = carry {
        of + a10 * b01 + a09 * b02 + a08 * b03 + a07 * b04 + a06 * b05 + a05 * b06 + a04 * b07 + a03 * b08 + a02 * b09 + a01 * b10,
        a10 * b02 + a09 * b03 + a08 * b04 + a07 * b05 + a06 * b06 + a05 * b07 + a04 * b08 + a03 * b09 + a02 * b10,
        a10 * b03 + a09 * b04 + a08 * b05 + a07 * b06 + a06 * b07 + a05 * b08 + a04 * b09 + a03 * b10,
        a10 * b04 + a09 * b05 + a08 * b06 + a07 * b07 + a06 * b08 + a05 * b09 + a04 * b10,
        a10 * b05 + a09 * b06 + a08 * b07 + a07 * b08 + a06 * b09 + a05 * b10,
        a10 * b06 + a09 * b07 + a08 * b08 + a07 * b09 + a06 * b10,
        a10 * b07 + a09 * b08 + a08 * b09 + a07 * b10,
        a10 * b08 + a09 * b09 + a08 * b10,
        a10 * b09 + a09 * b10,
        a10 * b10,
        0
    }

    -- Strip overflow (it's always 0).
    high[12] = nil

    return low, high
end

--- Computes a double-width sum of two numbers.
--
-- @tparam {number...} a0 The low part of a as 11 limbs in [0..2²⁴).
-- @tparam {number...} a1 The high part of a as 11 limbs in [0..2²⁴).
-- @tparam {number...} b0 The low part of b as 11 limbs in [0..2²⁴).
-- @tparam {number...} b1 The high part of b as 11 limbs in [0..2²⁴).
-- @treturn {number...} The low part of a + b as 11 limbs in [0..2²⁴).
-- @treturn {number...} The high part of a + b as 12 limbs in [0..2²⁴).
--
local function dwadd(a0, a1, b0, b1)
    local low = carry(add(a0, b0))
    local high = add(a1, b1)
    high[1] = high[1] + low[12]
    low[12] = nil
    return low, carry(high)
end

--- Computes half of a number.
--
-- @tparam {number...} a An even positive integer as 11 limbs in (-2²⁴..2²⁴).
-- @treturn {number...} a ÷ 2 as 11 limbs in (-2⁴⁷..2⁴⁷).
--
local function half(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)

    return {
        a00 + a01 * 2 ^ 23,
        a02 * 2 ^ 23,
        a03 * 2 ^ 23,
        a04 * 2 ^ 23,
        a05 * 2 ^ 23,
        a06 * 2 ^ 23,
        a07 * 2 ^ 23,
        a08 * 2 ^ 23,
        a09 * 2 ^ 23,
        a10 * 2 ^ 23,
        0,
    }
end

--- Computes a third of a number.
--
-- @tparam {number...} a A positive multiple of 3 as 11 limbs in (-2²⁶..2²⁶).
-- @treturn {number...} a ÷ 3 as 11 limbs in (-2²⁴..2²⁴).
--
local function third(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)

    local d00 = a00 * 0xaaaaaa
    local d01 = a01 * 0xaaaaaa + d00
    local d02 = a02 * 0xaaaaaa + d01
    local d03 = a03 * 0xaaaaaa + d02
    local d04 = a04 * 0xaaaaaa + d03
    local d05 = a05 * 0xaaaaaa + d04
    local d06 = a06 * 0xaaaaaa + d05
    local d07 = a07 * 0xaaaaaa + d06
    local d08 = a08 * 0xaaaaaa + d07
    local d09 = a09 * 0xaaaaaa + d08
    local d10 = a10 * 0xaaaaaa + d09

    local out = carryWeak {
        a00 + d00,
        a01 + d01,
        a02 + d02,
        a03 + d03,
        a04 + d04,
        a05 + d05,
        a06 + d06,
        a07 + d07,
        a08 + d08,
        a09 + d09,
        a10 + d10,
    }

    -- We compute the modular division mod 2²⁶⁴. out[12] isn't 0 but it's not
    -- part of a ÷ 3 either.
    out[12] = nil

    return out
end

--- Computes a number modulo 2.
--
-- @tparam {number...} a A number as 11 limbs in (-2²⁶, 2²⁶).
-- @treturn number a mod 2.
--
local function mod2(a)
    return a[1] % 2
end

--- Computes a number modulo 3.
--
-- @tparam {number...} a A number as 11 limbs in (-2²⁶, 2²⁶).
-- @treturn number a mod 3.
--
local function mod3(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    return (a00 + a01 + a02 + a03 + a04 + a05 + a06 + a07 + a08 + a09 + a10) % 3
end

--- Computes a double representing the most-significant bits of a number.
--
-- @tparam {number...} a A number as 11 limbs in (-2⁴⁸..2⁴⁸).
-- @treturn number A floating-point approximation for the value of a.
--
local function approx(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10 = unpack(a)
    return a00
         + a01 * 2 ^ 24
         + a02 * 2 ^ 48
         + a03 * 2 ^ 72
         + a04 * 2 ^ 96
         + a05 * 2 ^ 120
         + a06 * 2 ^ 144
         + a07 * 2 ^ 168
         + a08 * 2 ^ 192
         + a09 * 2 ^ 216
         + a10 * 2 ^ 240
end

--- Compares two numbers for ordering.
--
-- @tparam {number...} a A number as 11 limbs in (-2²⁵..2²⁵).
-- @tparam {number...} b A number as 11 limbs in (-2²⁵..2²⁵).
-- @treturn number Some number x with x < 0 iff a < b and x = 0 iff a = b.
--
local function cmp(a, b)
    return approx(sub(a, b))
end

local function num(a)
    return {a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
end

return {
    carry = carry,
    carryWeak = carryWeak,
    add = add,
    sub = sub,
    dwadd = dwadd,
    lmul = lmul,
    mul = mul,
    half = half,
    third = third,
    mod2 = mod2,
    mod3 = mod3,
    approx = approx,
    cmp = cmp,
    num = num,
}
