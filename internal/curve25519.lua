--- Point arithmetic on the Curve25519 Montgomery curve.
--
-- :::note Internal Module
-- This module is meant for internal use within the library. Its API is unstable
-- and subject to change without major version bumps.
-- :::
--
-- <br />
--
-- @module[kind=internal] internal.curve25519
--

local fp     = require "ccryptolib.internal.fp"
local random = require "ccryptolib.random"

local function double(P1)
    local x1, z1 = P1[1], P1[2]
    local a = fp.add(x1, z1)
    local aa = fp.square(a)
    local b = fp.sub(x1, z1)
    local bb = fp.square(b)
    local c = fp.sub(aa, bb)
    local x3 = fp.mul(aa, bb)
    local z3 = fp.mul(c, fp.add(bb, fp.kmul(c, 121666)))
    return {x3, z3}
end

local function step(dxmul, dx, P1, P2)
    local x1, z1 = P1[1], P1[2]
    local x2, z2 = P2[1], P2[2]
    local a = fp.add(x1, z1)
    local aa = fp.square(a)
    local b = fp.sub(x1, z1)
    local bb = fp.square(b)
    local e = fp.sub(aa, bb)
    local c = fp.add(x2, z2)
    local d = fp.sub(x2, z2)
    local da = fp.mul(d, a)
    local cb = fp.mul(c, b)
    local x4 = fp.square(fp.add(da, cb))
    local z4 = dxmul(fp.square(fp.sub(da, cb)), dx)
    local x3 = fp.mul(aa, bb)
    local z3 = fp.mul(e, fp.add(bb, fp.kmul(e, 121666)))
    return {x3, z3}, {x4, z4}
end

--- Performs a Montgomery ladder operation with multiplication by 8.
--
-- @tparam function(a:internal.fp.fp1, dx:any):internal.fp.fpq dxmul A function
-- to multiply an element in Fp by dx.
-- @tparam any dx The base point's x coordinate. Z is assumed to be equal to 1.
-- @tparam {number...} bits The multiplier scalar divided by 8, in little-endian
-- bits.
--
local function ladder8(dxmul, dx, bits)
    local P = {fp.num(1), fp.num(0)}
    local Q = {fp.decode(random.random(32)), dxmul(z2, dx)}

    -- Standard ladder.
    for i = #bits, 1, -1 do
        if bits[i] == 0 then
            P, Q = step(dxmul, dx, P, Q)
        else
            Q, P = step(dxmul, dx, Q, P)
        end
    end

    -- Multiply by 8 (double 3 times).
    for _ = 1, 3 do P = double(P) end

    return fp.mul(P[1], fp.invert(P[2]))
end

return {
    ladder8 = ladder8,
}
