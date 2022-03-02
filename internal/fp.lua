--- Arithmetic on Curve25519's base field.
--
-- @module internal.fp
--

local unpack = unpack or table.unpack
local bxor = bit32.bxor
local band = bit32.band
local bor = bit32.bor

--- The modular square root of -1.
local I = {
    0958640 * 2 ^ 0,
    0826664 * 2 ^ 22,
    1613251 * 2 ^ 43,
    1041528 * 2 ^ 64,
    0013673 * 2 ^ 85,
    0387171 * 2 ^ 107,
    1824679 * 2 ^ 128,
    0313839 * 2 ^ 149,
    0709440 * 2 ^ 170,
    0122635 * 2 ^ 192,
    0262782 * 2 ^ 213,
    0712905 * 2 ^ 234,
}

--- The difference between a non-canonical number and its canonical equivalent.
local CDIFF = {
    2 ^ 22 - 19,
    (2 ^ 21 - 1) * 2 ^ 22,
    (2 ^ 21 - 1) * 2 ^ 43,
    (2 ^ 21 - 1) * 2 ^ 64,
    (2 ^ 22 - 1) * 2 ^ 85,
    (2 ^ 21 - 1) * 2 ^ 107,
    (2 ^ 21 - 1) * 2 ^ 128,
    (2 ^ 21 - 1) * 2 ^ 149,
    (2 ^ 22 - 1) * 2 ^ 170,
    (2 ^ 21 - 1) * 2 ^ 192,
    (2 ^ 21 - 1) * 2 ^ 213,
    (2 ^ 21 - 1) * 2 ^ 234,
}

--- A base field polynomial.
--
-- The Curve25519 paper represents its numbers as "polynomals" that slice the
-- bigint into a little-endian array of floats. Each float slice is such that
-- the (infinite precision) sum of all of them is equal to the represented
-- number.
--
-- For our implementation, we use an array of 12 floats. Each one has a specific
-- exponent and mantissa range.
--
-- <!-- My best wishes to whoever is doing the Markdown parsing. -->
-- <style>
--   table.mdt {
--     border-collapse: collapse;
--   }
--   table.mdt td, table.mdt th {
--     border: 1px solid #cccccc;
--     padding: 5px;
--     text-align: center;
--   }
--   table.mdt th {
--     background-color: var(--background-2);
--   }
-- </style>
-- <table class="mdt">
--   <tr><th>Index</th><th>Coefficient Range</th><th>Multiplier</th></tr>
--   <tr><td>  0  </td><td>   (-2²²..2²²)   </td><td>   2⁰     </td></tr>
--   <tr><td>  1  </td><td>   (-2²¹..2²¹)   </td><td>   2²²    </td></tr>
--   <tr><td>  2  </td><td>   (-2²¹..2²¹)   </td><td>   2⁴³    </td></tr>
--   <tr><td>  3  </td><td>   (-2²¹..2²¹)   </td><td>   2⁶⁴    </td></tr>
--   <tr><td>  4  </td><td>   (-2²²..2²²)   </td><td>   2⁸⁵    </td></tr>
--   <tr><td>  5  </td><td>   (-2²¹..2²¹)   </td><td>   2¹⁰⁷   </td></tr>
--   <tr><td>  6  </td><td>   (-2²¹..2²¹)   </td><td>   2¹²⁸   </td></tr>
--   <tr><td>  7  </td><td>   (-2²¹..2²¹)   </td><td>   2¹⁴⁹   </td></tr>
--   <tr><td>  8  </td><td>   (-2²²..2²²)   </td><td>   2¹⁷⁰   </td></tr>
--   <tr><td>  9  </td><td>   (-2²¹..2²¹)   </td><td>   2¹⁹²   </td></tr>
--   <tr><td> 10  </td><td>   (-2²¹..2²¹)   </td><td>   2²¹³   </td></tr>
--   <tr><td> 11  </td><td>   (-2²¹..2²¹)   </td><td>   2²³⁴   </td></tr>
-- </table>
--
-- @type fp
--
local fp = nil
if fp ~= nil then return end

--- A nonnegative @{fp}.
--
-- This type represents elements that have no negative coefficients.
--
-- @type fpAbs
--
local fpAbs = nil
if fpAbs ~= nil then return end

--- An uncarried @{fp}.
--
-- This type represents elements that have coefficients in a wider range than
-- the limits specified in @{fp}. Specifically, this represents all the results
-- of uncarried float-wise additions of two elements.
--
-- @type fpUncarried
--
local fpUncarried = nil
if fpUncarried ~= nil then return end

--- Converts a Lua number to an element.
--
-- @tparam number n A number n in [0..2²²).
-- @treturn fpAbs n as a base field element.
--
local function num(n)
    return {n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
end

--- Adds two elements.
--
-- @tparam fp a
-- @tparam fp b
-- @treturn fpUncarried
--
local function add(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
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
        a11 + b11,
    }
end

--- Negates an element.
--
-- @tparam fp a
-- @treturn fp
--
local function neg(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    return {
        -a00,
        -a01,
        -a02,
        -a03,
        -a04,
        -a05,
        -a06,
        -a07,
        -a08,
        -a09,
        -a10,
        -a11,
    }
end

--- Subtracts an element from another.
--
-- If both elements are positive, then the result can be guaranteed to fit in
-- a single @{fp} without needing any carrying.
--
-- @tparam[1] fp a
-- @tparam[1] fp b
-- @treturn[1] fpUncarried
--
-- @tparam[2] fpAbs a
-- @tparam[2] fpAbs b
-- @treturn[2] fp
--
local function sub(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
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
        a11 - b11,
    }
end

--- Carries an element.
--
-- @tparam fpUncarried a
-- @treturn fpAbs
--
local function carry(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local r00, r01, r02, r03, r04, r05, r06, r07, r08, r09, r10, r11

    r11 = a11 % 2 ^ 255
    a00 = a00 + (a11 - r11) * (19 / 2 ^ 255)

    r00 = a00 % 2 ^ 22  a01 = a01 + (a00 - r00)
    r01 = a01 % 2 ^ 43  a02 = a02 + (a01 - r01)
    r02 = a02 % 2 ^ 64  a03 = a03 + (a02 - r02)
    r03 = a03 % 2 ^ 85  a04 = a04 + (a03 - r03)
    r04 = a04 % 2 ^ 107 a05 = a05 + (a04 - r04)
    r05 = a05 % 2 ^ 128 a06 = a06 + (a05 - r05)
    r06 = a06 % 2 ^ 149 a07 = a07 + (a06 - r06)
    r07 = a07 % 2 ^ 170 a08 = a08 + (a07 - r07)
    r08 = a08 % 2 ^ 192 a09 = a09 + (a08 - r08)
    r09 = a09 % 2 ^ 213 a10 = a10 + (a09 - r09)
    r10 = a10 % 2 ^ 234 a11 = r11 + (a10 - r10)

    r11 = a11 % 2 ^ 255 r00 = r00 + (a11 - r11) * (19 / 2 ^ 255)

    return {r00, r01, r02, r03, r04, r05, r06, r07, r08, r09, r10, r11}
end

--- Returns whether the modp number is the canonical representative.
--
-- @see canonicalize
--
-- @tparam fpAbs a
-- @treturn boolean
--
local function isCanonical(a)
    local e11 = bxor(a[12] * 2 ^ -234, 2 ^ 21 - 1)
    local e10 = bxor(a[11] * 2 ^ -213, 2 ^ 21 - 1)
    local e09 = bxor(a[10] * 2 ^ -192, 2 ^ 21 - 1)
    local e08 = bxor(a[09] * 2 ^ -170, 2 ^ 22 - 1)
    local e07 = bxor(a[08] * 2 ^ -149, 2 ^ 21 - 1)
    local e06 = bxor(a[07] * 2 ^ -128, 2 ^ 21 - 1)
    local e05 = bxor(a[06] * 2 ^ -107, 2 ^ 21 - 1)
    local e04 = bxor(a[05] * 2 ^ -85, 2 ^ 22 - 1)
    local e03 = bxor(a[04] * 2 ^ -64, 2 ^ 21 - 1)
    local e02 = bxor(a[03] * 2 ^ -43, 2 ^ 21 - 1)
    local e01 = bxor(a[02] * 2 ^ -22, 2 ^ 21 - 1)
    local e00 = band(a[01] - (2 ^ 22 - 19), 2 ^ 31)
    return 0 ~= bor(e00, e01, e02, e03, e04, e05, e06, e07, e08, e09, e10, e11)
end

--- Returns the canoncal representative of a modp number.
--
-- Some elements can be represented by two different arrays of floats. This
-- returns the canonical element of the represented equivalence class. We define
-- an element as canonical if it's the smallest nonnegative number in its class.
--
-- @tparam fp a
-- @treturn fpAbs
--
local function canonicalize(a)
    a = carry(a)
    local zero = num(0)
    local diff = isCanonical(a) and zero or CDIFF
    return sub(a, diff)
end

--- Returns whether two elements are the same.
--
-- @tparam fpAbs a
-- @tparam fpAbs b
-- @treturn boolean
--
local function eq(a, b)
    a = canonicalize(a)
    b = canonicalize(b)
    for i = 1, 12 do
        if a[i] ~= b[i] then
            return false
        end
    end
    return true
end

--- Multiplies two elements.
--
-- @tparam fpUncarried a
-- @tparam fpUncarried b
-- @treturn fpAbs
--
local function mul(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
    local c00, c01, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11

    -- Multiply high half into c00..c11.
    c00 = a11 * b01
        + a10 * b02
        + a09 * b03
        + a08 * b04
        + a07 * b05
        + a06 * b06
        + a05 * b07
        + a04 * b08
        + a03 * b09
        + a02 * b10
        + a01 * b11
    c01 = a11 * b02
        + a10 * b03
        + a09 * b04
        + a08 * b05
        + a07 * b06
        + a06 * b07
        + a05 * b08
        + a04 * b09
        + a03 * b10
        + a02 * b11
    c02 = a11 * b03
        + a10 * b04
        + a09 * b05
        + a08 * b06
        + a07 * b07
        + a06 * b08
        + a05 * b09
        + a04 * b10
        + a03 * b11
    c03 = a11 * b04
        + a10 * b05
        + a09 * b06
        + a08 * b07
        + a07 * b08
        + a06 * b09
        + a05 * b10
        + a04 * b11
    c04 = a11 * b05
        + a10 * b06
        + a09 * b07
        + a08 * b08
        + a07 * b09
        + a06 * b10
        + a05 * b11
    c05 = a11 * b06
        + a10 * b07
        + a09 * b08
        + a08 * b09
        + a07 * b10
        + a06 * b11
    c06 = a11 * b07
        + a10 * b08
        + a09 * b09
        + a08 * b10
        + a07 * b11
    c07 = a11 * b08
        + a10 * b09
        + a09 * b10
        + a08 * b11
    c08 = a11 * b09
        + a10 * b10
        + a09 * b11
    c09 = a11 * b10
        + a10 * b11
    c10 = a11 * b11

    -- Multiply low half with reduction into c00..c11.
    c00 = c00 * (19 / 2 ^ 255)
        + a00 * b00
    c01 = c01 * (19 / 2 ^ 255)
        + a01 * b00
        + a00 * b01
    c02 = c02 * (19 / 2 ^ 255)
        + a02 * b00
        + a01 * b01
        + a00 * b02
    c03 = c03 * (19 / 2 ^ 255)
        + a03 * b00
        + a02 * b01
        + a01 * b02
        + a00 * b03
    c04 = c04 * (19 / 2 ^ 255)
        + a04 * b00
        + a03 * b01
        + a02 * b02
        + a01 * b03
        + a00 * b04
    c05 = c05 * (19 / 2 ^ 255)
        + a05 * b00
        + a04 * b01
        + a03 * b02
        + a02 * b03
        + a01 * b04
        + a00 * b05
    c06 = c06 * (19 / 2 ^ 255)
        + a06 * b00
        + a05 * b01
        + a04 * b02
        + a03 * b03
        + a02 * b04
        + a01 * b05
        + a00 * b06
    c07 = c07 * (19 / 2 ^ 255)
        + a07 * b00
        + a06 * b01
        + a05 * b02
        + a04 * b03
        + a03 * b04
        + a02 * b05
        + a01 * b06
        + a00 * b07
    c08 = c08 * (19 / 2 ^ 255)
        + a08 * b00
        + a07 * b01
        + a06 * b02
        + a05 * b03
        + a04 * b04
        + a03 * b05
        + a02 * b06
        + a01 * b07
        + a00 * b08
    c09 = c09 * (19 / 2 ^ 255)
        + a09 * b00
        + a08 * b01
        + a07 * b02
        + a06 * b03
        + a05 * b04
        + a04 * b05
        + a03 * b06
        + a02 * b07
        + a01 * b08
        + a00 * b09
    c10 = c10 * (19 / 2 ^ 255)
        + a10 * b00
        + a09 * b01
        + a08 * b02
        + a07 * b03
        + a06 * b04
        + a05 * b05
        + a04 * b06
        + a03 * b07
        + a02 * b08
        + a01 * b09
        + a00 * b10
    c11 = a11 * b00
        + a10 * b01
        + a09 * b02
        + a08 * b03
        + a07 * b04
        + a06 * b05
        + a05 * b06
        + a04 * b07
        + a03 * b08
        + a02 * b09
        + a01 * b10
        + a00 * b11

    -- Carry and reduce.
    a10 = c10 % 2 ^ 234 c11 = c11 + (c10 - a10)
    a11 = c11 % 2 ^ 255 c00 = c00 + (c11 - a11) * (19 / 2 ^ 255)

    a00 = c00 % 2 ^ 22  c01 = c01 + (c00 - a00)
    a01 = c01 % 2 ^ 43  c02 = c02 + (c01 - a01)
    a02 = c02 % 2 ^ 64  c03 = c03 + (c02 - a02)
    a03 = c03 % 2 ^ 85  c04 = c04 + (c03 - a03)
    a04 = c04 % 2 ^ 107 c05 = c05 + (c04 - a04)
    a05 = c05 % 2 ^ 128 c06 = c06 + (c05 - a05)
    a06 = c06 % 2 ^ 149 c07 = c07 + (c06 - a06)
    a07 = c07 % 2 ^ 170 c08 = c08 + (c07 - a07)
    a08 = c08 % 2 ^ 192 c09 = c09 + (c08 - a08)
    a09 = c09 % 2 ^ 213 c10 = a10 + (c09 - a09)
    a10 = c10 % 2 ^ 234 c11 = a11 + (c10 - a10)

    a11 = c11 % 2 ^ 255 a00 = a00 + (c11 - a11) * (19 / 2 ^ 255)

    return {a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11}
end

--- Squares an element.
--
-- @tparam fpUncarried a
-- @treturn fpAbs
--
local function square(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local d00, d01, d02, d03, d04, d05, d06, d07, d08, d09, d10
    local c00, c01, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11

    -- Compute 2a.
    d00 = a00 + a00
    d01 = a01 + a01
    d02 = a02 + a02
    d03 = a03 + a03
    d04 = a04 + a04
    d05 = a05 + a05
    d06 = a06 + a06
    d07 = a07 + a07
    d08 = a08 + a08
    d09 = a09 + a09
    d10 = a10 + a10

    -- Multiply high half into c00..c11.
    c00 = a11 * d01
        + a10 * d02
        + a09 * d03
        + a08 * d04
        + a07 * d05
        + a06 * a06
    c01 = a11 * d02
        + a10 * d03
        + a09 * d04
        + a08 * d05
        + a07 * d06
    c02 = a11 * d03
        + a10 * d04
        + a09 * d05
        + a08 * d06
        + a07 * a07
    c03 = a11 * d04
        + a10 * d05
        + a09 * d06
        + a08 * d07
    c04 = a11 * d05
        + a10 * d06
        + a09 * d07
        + a08 * a08
    c05 = a11 * d06
        + a10 * d07
        + a09 * d08
    c06 = a11 * d07
        + a10 * d08
        + a09 * a09
    c07 = a11 * d08
        + a10 * d09
    c08 = a11 * d09
        + a10 * a10
    c09 = a11 * d10
    c10 = a11 * a11

    -- Multiply low half with reduction into c00..c11.
    c00 = c00 * (19 / 2 ^ 255)
        + a00 * a00
    c01 = c01 * (19 / 2 ^ 255)
        + a01 * d00
    c02 = c02 * (19 / 2 ^ 255)
        + a02 * d00
        + a01 * a01
    c03 = c03 * (19 / 2 ^ 255)
        + a03 * d00
        + a02 * d01
    c04 = c04 * (19 / 2 ^ 255)
        + a04 * d00
        + a03 * d01
        + a02 * a02
    c05 = c05 * (19 / 2 ^ 255)
        + a05 * d00
        + a04 * d01
        + a03 * d02
    c06 = c06 * (19 / 2 ^ 255)
        + a06 * d00
        + a05 * d01
        + a04 * d02
        + a03 * a03
    c07 = c07 * (19 / 2 ^ 255)
        + a07 * d00
        + a06 * d01
        + a05 * d02
        + a04 * d03
    c08 = c08 * (19 / 2 ^ 255)
        + a08 * d00
        + a07 * d01
        + a06 * d02
        + a05 * d03
        + a04 * a04
    c09 = c09 * (19 / 2 ^ 255)
        + a09 * d00
        + a08 * d01
        + a07 * d02
        + a06 * d03
        + a05 * d04
    c10 = c10 * (19 / 2 ^ 255)
        + a10 * d00
        + a09 * d01
        + a08 * d02
        + a07 * d03
        + a06 * d04
        + a05 * a05
    c11 = a11 * d00
        + a10 * d01
        + a09 * d02
        + a08 * d03
        + a07 * d04
        + a06 * d05

    -- Carry and reduce.
    a10 = c10 % 2 ^ 234 c11 = c11 + (c10 - a10)
    a11 = c11 % 2 ^ 255 c00 = c00 + (c11 - a11) * (19 / 2 ^ 255)

    a00 = c00 % 2 ^ 22  c01 = c01 + (c00 - a00)
    a01 = c01 % 2 ^ 43  c02 = c02 + (c01 - a01)
    a02 = c02 % 2 ^ 64  c03 = c03 + (c02 - a02)
    a03 = c03 % 2 ^ 85  c04 = c04 + (c03 - a03)
    a04 = c04 % 2 ^ 107 c05 = c05 + (c04 - a04)
    a05 = c05 % 2 ^ 128 c06 = c06 + (c05 - a05)
    a06 = c06 % 2 ^ 149 c07 = c07 + (c06 - a06)
    a07 = c07 % 2 ^ 170 c08 = c08 + (c07 - a07)
    a08 = c08 % 2 ^ 192 c09 = c09 + (c08 - a08)
    a09 = c09 % 2 ^ 213 c10 = a10 + (c09 - a09)
    a10 = c10 % 2 ^ 234 c11 = a11 + (c10 - a10)

    a11 = c11 % 2 ^ 255 a00 = a00 + (c11 - a11) * (19 / 2 ^ 255)

    return {a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11}
end

--- Multiplies an element by a number.
--
-- @tparam fpUncarried a
-- @tparam number k A number k in [0..2²¹).
-- @treturn fpAbs
--
local function kmul(a, k)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)

    -- TODO WHY ARE TYPE CONSTRAINTS SO DIFFICULT TO SPECIFY
    return carry {
        a00 * k,
        a01 * k,
        a02 * k,
        a03 * k,
        a04 * k,
        a05 * k,
        a06 * k,
        a07 * k,
        a08 * k,
        a09 * k,
        a10 * k,
        a11 * k,
    }
end

--- Squares a modp number n times.
--
-- @tparam fpUncarried a
-- @tparam number n
-- @treturn fpAbs
--
local function nsquare(a, n)
    for _ = 1, n do a = square(a) end
    return a
end

--- Computes the inverse of an element.
--
-- Computation of the inverse requires 11 multiplicationss and 252 squarings.
--
-- @tparam fpUncarried a
-- @treturn[1] fpAbs a⁻¹
-- @treturn[2] fpAbs 0 if the argument is 0, which has no inverse.
--
local function invert(a)
    local a2 = square(a)
    local a9 = mul(a, nsquare(a2, 2))
    local a11 = mul(a9, a2)

    local x5 = mul(square(a11), a9)
    local x10 = mul(nsquare(x5, 5), x5)
    local x20 = mul(nsquare(x10, 10), x10)
    local x40 = mul(nsquare(x20, 20), x20)
    local x50 = mul(nsquare(x40, 10), x10)
    local x100 = mul(nsquare(x50, 50), x50)
    local x200 = mul(nsquare(x100, 100), x100)
    local x250 = mul(nsquare(x200, 50), x50)

    return mul(nsquare(x250, 5), a11)
end

--- Returns an element x that satisfies v * x² = u.
--
-- Note that when v = 0, the returned value can take any @{fpAbs} value.
--
-- @tparam fpUncarried u
-- @tparam fpUncarried v
-- @treturn[1] fpAbs x
-- @treturn[2] nil if there is no solution.
--
local function sqrtDiv(u, v)
    u = carry(u)

    local v2 = square(v)
    local v3 = mul(v, v2)
    local v6 = square(v3)
    local v7 = mul(v, v6)
    local uv7 = mul(u, v7)

    local x2 = mul(square(uv7), uv7)
    local x4 = mul(nsquare(x2, 2), x2)
    local x8 = mul(nsquare(x4, 4), x4)
    local x16 = mul(nsquare(x8, 8), x8)
    local x18 = mul(nsquare(x16, 2), x2)
    local x32 = mul(nsquare(x16, 16), x16)
    local x50 = mul(nsquare(x32, 18), x18)
    local x100 = mul(nsquare(x50, 50), x50)
    local x200 = mul(nsquare(x100, 100), x100)
    local x250 = mul(nsquare(x200, 50), x50)
    local pr = mul(nsquare(x250, 2), uv7)

    local uv3 = mul(u, v3)
    local b = mul(uv3, pr)
    local b2 = square(b)
    local vb2 = mul(v, b2)

    if not eq(vb2, u) then
        -- Found sqrt(-u/v), multiply by i.
        b = mul(b, I)
        b2 = square(b)
        vb2 = mul(v, b2)
    end

    if eq(vb2, u) then
        return b
    else
        return nil
    end
end

--- Encodes an element in little-endian.
--
-- @tparam fpAbs a
-- @treturn string A 32-byte string. Always represents the canonical element.
--
local function encode(a)
    a = canonicalize(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)

    local bytes = {}
    local acc = a00

    local function putBytes(n)
        for _ = 1, n do
            local byte = acc % 256
            bytes[#bytes + 1] = byte
            acc = (acc - byte) / 256
        end
    end

    putBytes(2) acc = acc + a01 / 2 ^ 16
    putBytes(3) acc = acc + a02 / 2 ^ 40
    putBytes(3) acc = acc + a03 / 2 ^ 64
    putBytes(2) acc = acc + a04 / 2 ^ 80
    putBytes(3) acc = acc + a05 / 2 ^ 104
    putBytes(3) acc = acc + a06 / 2 ^ 128
    putBytes(2) acc = acc + a07 / 2 ^ 144
    putBytes(3) acc = acc + a08 / 2 ^ 168
    putBytes(3) acc = acc + a09 / 2 ^ 192
    putBytes(2) acc = acc + a10 / 2 ^ 208
    putBytes(3) acc = acc + a11 / 2 ^ 232
    putBytes(3)

    return string.char(unpack(bytes))
end

--- Decodes an element in little-endian.
--
-- @tparam string b A 32-byte string. The most-significant bit is discarded.
-- @treturn fpAbs The decoded element. May not be canonical.
--
local function decode(b)
    local w00, w01, w02, w03, w04, w05, w06, w07, w08, w09, w10, w11 =
        ("<I3I3I2I3I3I2I3I3I2I3I3I2"):unpack(b)

    w11 = w11 % 2 ^ 15

    return carry {
        w00,
        w01 * 2 ^ 24,
        w02 * 2 ^ 48,
        w03 * 2 ^ 64,
        w04 * 2 ^ 88,
        w05 * 2 ^ 112,
        w06 * 2 ^ 128,
        w07 * 2 ^ 152,
        w08 * 2 ^ 176,
        w09 * 2 ^ 192,
        w10 * 2 ^ 216,
        w11 * 2 ^ 240,
    }
end

return {
    num = num,
    add = add,
    neg = neg,
    sub = sub,
    kmul = kmul,
    mul = mul,
    canonicalize = canonicalize,
    square = square,
    carry = carry,
    invert = invert,
    sqrtDiv = sqrtDiv,
    encode = encode,
    decode = decode,
}
