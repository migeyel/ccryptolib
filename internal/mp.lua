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

--- Carries a number in base 2²⁴.
--
-- @tparam {number...} a A number 0 <= a < 2 ^ (24 × (#a + 1)) as limbs in
-- [-2⁵²..2⁵²].
-- @treturn {number...} a as #a + 1 limbs in [0..2²⁴).
--
local function carry(a)
    local c = {unpack(a)}
    c[#c + 1] = 0
    for i = 1, #c - 1 do
        local val = c[i]
        local rem = val % 2 ^ 24
        local quot = (val - rem) / 2 ^ 24
        c[i + 1] = c[i + 1] + quot
        c[i] = rem
    end
    return c
end

--- Adds two numbers.
--
-- @tparam {number...} a An array limbs in [0..2²⁴).
-- @tparam {number...} b An array of #a limbs in [0..2²⁴).
-- @treturn {number...} a + b as #a + 1 limbs in [0..2²⁴).
--
local function add(a, b)
    local c = {}
    for i = 1, #a do
        c[i] = a[i] + b[i]
    end

    -- c's limbs fit in [-2²⁵..2²⁵], since addition adds at most one bit.
    return carry(c)
end

--- Multiplies two numbers.
--
-- @tparam {number...} a An array of 11 limbs in [0..2²⁴).
-- @tparam {number...} b An array of 11 limbs in [0..2²⁴).
-- @treturn {number...} a × b as 22 limbs in [0..2²⁴).
--
local function mul(a, b)
    local c = {}
    for i = 1, 21 do c[i] = 0 end
    for i = 1, 11 do
        for j = 1, 11 do
            local k = i + j - 1
            c[k] = c[k] + a[i] * b[j]
        end
    end

    -- {a, b} < 2²⁶⁴ means that c < 2⁵²⁸ = 2 ^ (24 × (21 + 1)).
    -- c's limbs are smaller than 2⁴⁸ × 11 < 2⁵², since multiplication doubles
    -- bit length, and 11 multiplied limbs are added together.
    return carry(c)
end

return {
    carry = carry,
    add = add,
    mul = mul,
}
