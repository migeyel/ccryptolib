--- Point arithmetic on the Edwards25519 Edwards curve.
--
-- :::note Internal Module
-- This module is meant for internal use within the library. Its API is unstable
-- and subject to change without major version bumps.
-- :::
--
-- <br />
--
-- @module[kind=internal] internal.edwards25519
--

local fp = require "ccryptolib.internal.fp"

local unpack = unpack or table.unpack

local D = fp.mul(fp.num(-121665), fp.invert(fp.num(121666)))
local K = fp.kmul(D, 2)

local O = {fp.num(0), fp.num(1), fp.num(1), fp.num(0)}
local G = nil

--- Doubles a point.
--
-- @tparam point P1 The point to double.
-- @treturn point Twice P1.
--
local function double(P1)
    -- Unsoundness: fp.sub(g, e), and fp.sub(d, i) break fp.sub's contract since
    -- it doesn't accept an fp2. Although not ideal, in practice this doesn't
    -- matter since fp.carry handles the larger sum.
    local P1x, P1y, P1z = unpack(P1)
    local a = fp.square(P1x)
    local b = fp.square(P1y)
    local c = fp.square(P1z)
    local d = fp.add(c, c)
    local e = fp.add(a, b)
    local f = fp.add(P1x, P1y)
    local g = fp.square(f)
    local h = fp.carry(fp.sub(g, e))
    local i = fp.sub(b, a)
    local j = fp.carry(fp.sub(d, i))
    local P3x = fp.mul(h, j)
    local P3y = fp.mul(i, e)
    local P3z = fp.mul(j, i)
    local P3t = fp.mul(h, e)
    return {P3x, P3y, P3z, P3t}
end

--- Adds two points.
--
-- @tparam point P1 The first summand point.
-- @tparam niels N1 The second summand point, in Niels form. See @{niels}.
-- @treturn point The sum.
--
local function add(P1, N1)
    local P1x, P1y, P1z, P1t = unpack(P1)
    local N1p, N1m, N1z, N1t = unpack(N1)
    local a = fp.sub(P1y, P1x)
    local b = fp.mul(a, N1m)
    local c = fp.add(P1y, P1x)
    local d = fp.mul(c, N1p)
    local e = fp.mul(P1t, N1t)
    local f = fp.mul(P1z, N1z)
    local g = fp.sub(d, b)
    local h = fp.sub(f, e)
    local i = fp.add(f, e)
    local j = fp.add(d, b)
    local P3x = fp.mul(g, h)
    local P3y = fp.mul(i, j)
    local P3z = fp.mul(h, i)
    local P3t = fp.mul(g, j)
    return {P3x, P3y, P3z, P3t}
end

local function sub(P1, N1)
    local P1x, P1y, P1z, P1t = unpack(P1)
    local N1p, N1m, N1z, N1t = unpack(N1)
    local a = fp.sub(P1y, P1x)
    local b = fp.mul(a, N1p)
    local c = fp.add(P1y, P1x)
    local d = fp.mul(c, N1m)
    local e = fp.mul(P1t, N1t)
    local f = fp.mul(P1z, N1z)
    local g = fp.sub(d, b)
    local h = fp.add(f, e)
    local i = fp.sub(f, e)
    local j = fp.add(d, b)
    local P3x = fp.mul(g, h)
    local P3y = fp.mul(i, j)
    local P3z = fp.mul(h, i)
    local P3t = fp.mul(g, j)
    return {P3x, P3y, P3z, P3t}
end

--- Computes the Niels representation of a point.
--
-- @tparam point P1
-- @treturn niels P1's Niels representation.
--
local function niels(P1)
    local P1x, P1y, P1z, P1t = unpack(P1)
    local N3p = fp.add(P1y, P1x)
    local N3m = fp.sub(P1y, P1x)
    local N3z = fp.add(P1z, P1z)
    local N3t = fp.mul(P1t, K)
    return {N3p, N3m, N3z, N3t}
end

local function scale(P1)
    local P1x, P1y, P1z = unpack(P1)
    local zInv = fp.invert(P1z)
    local P3x = fp.mul(P1x, zInv)
    local P3y = fp.mul(P1y, zInv)
    local P3z = fp.num(1)
    local P3t = fp.mul(P3x, P3y)
    return {P3x, P3y, P3z, P3t}
end

--- Encodes a point.
--
-- @tparam point P1 The scaled point to encode.
-- @treturn string The 32-byte encoded point.
--
local function encode(P1)
    P1 = scale(P1)
    local P1x, P1y = unpack(P1)
    local y = fp.encode(P1y)
    local xBit = fp.canonicalize(P1x)[1] % 2
    return y:sub(1, -2) .. string.char(y:byte(-1) + xBit * 128)
end

--- Decodes a point.
--
-- @tparam string str A 32-byte encoded point.
-- @treturn[1] point The decoded point.
-- @treturn[2] nil If the string did not represent a valid encoded point.
--
local function decode(str)
    local P3y = fp.decode(str)
    local a = fp.square(P3y)
    local b = fp.sub(a, fp.num(1))
    local c = fp.mul(a, D)
    local d = fp.add(c, fp.num(1))
    local P3x = fp.sqrtDiv(b, d)
    if not P3x then return nil end
    local xBit = fp.canonicalize(P3x)[1] % 2
    if xBit ~= bit32.extract(str:byte(-1), 7) then
        P3x = fp.carry(fp.neg(P3x))
    end
    local P3z = fp.num(1)
    local P3t = fp.mul(P3x, P3y)
    return {P3x, P3y, P3z, P3t}
end

G = decode("Xfffffffffffffffffffffffffffffff")

local function signedRadixW(bits, w)
    -- TODO Find a more elegant way of doing this.
    local wPow = 2 ^ w
    local wPowh = wPow / 2
    local out = {}
    local acc = 0
    local mul = 1
    for i = 1, #bits do
        acc = acc + bits[i] * mul
        mul = mul * 2
        while i == #bits and acc > 0 or mul > wPow do
            local rem = acc % wPow
            if rem >= wPowh then rem = rem - wPow end
            acc = (acc - rem) / wPow
            mul = mul / wPow
            out[#out + 1] = rem
        end
    end
    return out
end

local function radixWTable(P, w)
    local out = {}
    for i = 1, math.ceil(255 / w) do
        local row = {niels(P)}
        for j = 2, 2 ^ w / 2 do
            P = add(P, row[1])
            row[j] = niels(P)
        end
        out[i] = row
        P = double(P)
    end
    return out
end

local G_W = 5
local G_TABLE = radixWTable(G, G_W)

local function WNAF(bits, w)
    -- TODO Find a more elegant way of doing this.
    local wPow = 2 ^ w
    local wPowh = wPow / 2
    local out = {}
    local acc = 0
    local mul = 1
    for i = 1, #bits do
        acc = acc + bits[i] * mul
        mul = mul * 2
        while i == #bits and acc > 0 or mul > wPow do
            if acc % 2 == 0 then
                acc = acc / 2
                mul = mul / 2
                out[#out + 1] = 0
            else
                local rem = acc % wPow
                if rem >= wPowh then rem = rem - wPow end
                acc = acc - rem
                out[#out + 1] = rem
            end
        end
    end
    while out[#out] == 0 do out[#out] = nil end
    return out
end

local function WNAFTable(P, w)
    local dP = double(P)
    local out = {niels(P)}
    for i = 3, 2 ^ w, 2 do
        out[i] = niels(add(dP, out[i - 2]))
    end
    return out
end

--- Performs a scalar multiplication by the base point G.
--
-- @tparam {number...} bits The scalar multiplier, in little-endian bits.
-- @treturn point The product.
--
local function mulG(bits)
    local sw = signedRadixW(bits, G_W)
    local R = O
    for i = 1, #sw do
        local b = sw[i]
        if b > 0 then
            R = add(R, G_TABLE[i][b])
        elseif b < 0 then
            R = sub(R, G_TABLE[i][-b])
        end
    end
    return R
end

--- Performs a scalar multiplication operation.
--
-- @tparam point P The base point.
-- @tparam {number...} bits The scalar multiplier, in little-endian bits.
-- @treturn point The product.
--
local function mul(P, bits)
    local naf = WNAF(bits, 5)
    local tbl = WNAFTable(P, 5)
    local R = O
    for i = #naf, 1, -1 do
        local b = naf[i]
        if b == 0 then
            R = double(R)
        elseif b > 0 then
            R = add(R, tbl[b])
        else
            R = sub(R, tbl[-b])
        end
    end
    return R
end

return {
    double = double,
    add = add,
    niels = niels,
    encode = encode,
    decode = decode,
    mulG = mulG,
    mul = mul,
}
