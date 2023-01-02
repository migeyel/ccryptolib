local expect = require "cc.expect".expect
local fq     = require "ccryptolib.internal.fq"
local fp     = require "ccryptolib.internal.fp"
local c25    = require "ccryptolib.internal.curve25519"
local random = require "ccryptolib.random"

local function mask(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    local mask = random.random(32)
    local x = fq.decodeClamped8(sk)
    local r = fq.decodeClamped8(mask)
    local xr = fq.sub(x, r)
    return fq.encode(xr), mask
end

local function remask(msk, oldMask)
    expect(1, msk, "string")
    assert(#msk == 32, "masked secret key length must be 32")
    expect(2, oldMask, "string")
    assert(#oldMask == 32, "old mask length must be 32")
    local newMask = random.random(32)
    local xr = fq.decode(msk)
    local r = fq.decodeClamped8(oldMask)
    local s = fq.decodeClamped8(newMask)
    local xs = fq.add(xr, fq.sub(r, s))
    return fq.encode(xs), newMask
end

local function exchangeOnPoint(msk, mask, P)
    local xr = fq.decode(msk)
    local r = fq.decodeClamped8(mask)
    local rP, xrP, dP = c25.prac(P, fq.makeRuleset(r, xr))

    -- Return early if P has small order or if r = xr. (1)
    if not rP then
        local out = fp.encode(fp.num(0))
        return out, out
    end

    local xP = c25.dadd(dP, rP, xrP)

    -- Extract coordinates for scaling.
    local xPx, xPz = xP[1], xP[2]
    local rPx, rPz = rP[1], rP[2]

    -- We're splitting the secret x into (x - r (mod q), r). The multiplication
    -- adds them back together, but this only works if P's order is q, which is
    -- not the case on the twist.
    -- As a result, we need to check if P is on the twist and return 0 so as to
    -- not leak part of x. We do this by checking the curve equation against P.
    -- The equation for Curve25519 is y² = x³ + 486662x² + x. Checking it
    -- amounts to verifying that x³ + 486662x² + x is a quadratic residue.
    local Px = P[1]
    local Px2 = fp.square(Px)
    local Px3 = fp.mul(Px2, Px)
    local APx2 = fp.kmul(Px2, 486662)
    local Py2 = fp.carry(fp.add(fp.carry(fp.add(Px3, APx2)), Px))

    -- Square the Z coordinate on both products.
    xPx, xPz = fp.mul(xPx, xPz), fp.square(xPz)
    rPx, rPz = fp.mul(rPx, rPz), fp.square(rPz)

    -- Find the square root of 1 / (Py2 * xPz * rPz).
    -- Neither rPz, xPz, nor Py2 are 0:
    -- - If Py2 was 0, then P would be low order, which would return at (1).
    -- - Since P isn't low order, clamping prevents the ladder from returning O.
    -- Since we've just squared both xPz and rPz, the root will exist iff Py2 is
    -- a quadratic residue. This checks the curve equation, so we're done.
    local root = fp.sqrtDiv(fp.num(1), fp.mul(fp.mul(xPz, rPz), Py2))
    if not root then return fp.encode(fp.num(0)) end

    -- Get the inverses of both Z values.
    local xPzrPzInv = fp.mul(fp.square(root), Py2)
    local xPzInv = fp.mul(xPzrPzInv, rPz)
    local rPzInv = fp.mul(xPzrPzInv, xPz)

    -- Finish scaling and encode the output.
    return fp.encode(fp.mul(xPx, xPzInv)), fp.encode(fp.mul(rPx, rPzInv))
end

--- Treats both shares as X25519 keys and performs a double key exchange.
--
-- Returns 0 if the input public key has small order or if it isn't in the base
-- curve. This is different from standard X25519, which performs the exchange
-- even on the twist.
--
-- May incorrectly return 0 with negligible chance if the mask happens to match
-- the masked key. I haven't checked if clamping prevents that from happening.
--
local function exchange(msk, mask, pk)
    expect(1, msk, "string")
    assert(#msk == 32, "masked secret key length must be 32")
    expect(2, mask, "string")
    assert(#mask == 32, "mask length must be 32")
    expect(3, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    return exchangeOnPoint(msk, mask, c25.decode(pk))
end

--- Same as @{exchange}, but decodes the public key as an Edwards25519 point.
local function exchangeEd(msk, mask, pk)
    expect(1, msk, "string")
    assert(#msk == 32, "masked secret key length must be 32")
    expect(2, mask, "string")
    assert(#mask == 32, "mask length must be 32")
    expect(3, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    return exchangeOnPoint(msk, mask, c25.decodeEd(pk))
end

return {
    mask = mask,
    remask = remask,
    exchange = exchange,
    exchangeEd = exchangeEd,
}
