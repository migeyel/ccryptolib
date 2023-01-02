local expect = require "cc.expect".expect
local fq     = require "ccryptolib.internal.fq"
local fp     = require "ccryptolib.internal.fp"
local c25    = require "ccryptolib.internal.curve25519"
local ed     = require "ccryptolib.internal.edwards25519"
local sha512 = require "ccryptolib.internal.sha512"
local random = require "ccryptolib.random"

--- Transforms an X25519 secret key into a masked key.
local function maskExchangeSk(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    local mask = random.random(32)
    local x = fq.decodeClamped(sk)
    local r = fq.decodeClamped(mask)
    local xr = fq.sub(x, r)
    return fq.encode(xr) .. mask
end

--- Transforms an Ed25519 secret key into a masked key.
function maskSignatureSk(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    return maskExchangeSk(sha512.digest(sk):sub(1, 32))
end

--- Rerandomizes the masking on a masked key.
local function remask(sk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    local newMask = random.random(32)
    local xr = fq.decode(sk:sub(1, 32))
    local r = fq.decodeClamped(sk:sub(33))
    local s = fq.decodeClamped(newMask)
    local xs = fq.add(xr, fq.sub(r, s))
    return fq.encode(xs) .. newMask
end

--- Returns the ephemeral exchange secret key of this masked key.
--
-- This is the second secret key in the "double key exchange" in @{exchange},
-- the first being the key that has been masked. The ephemeral key changes every
-- time @{remask} is called.
--
local function exchangeEsk(sk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    return sk:sub(33)
end

local function exchangeOnPoint(sk, P)
    local xr = fq.decode(sk:sub(1, 32))
    local r = fq.decodeClamped(sk:sub(33))
    local rP, xrP, dP = c25.prac(P, fq.makeRuleset(fq.eighth(r), fq.eighth(xr)))

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

--- Returns the X25519 public key of this masked key.
local function exchangePk(sk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    return (exchangeOnPoint(sk, c25.G))
end

--- Returns the Ed25519 public key of this masked key.
local function signaturePk(sk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    local xr = fq.decode(sk:sub(1, 32))
    local r = fq.decodeClamped(sk:sub(33))
    local y = ed.add(ed.mulG(fq.bits(xr)), ed.niels(ed.mulG(fq.bits(r))))
    return ed.encode(ed.scale(y))
end

--- Performs a double key exchange.
--
-- Returns 0 if the input public key has small order or if it isn't in the base
-- curve. This is different from standard X25519, which performs the exchange
-- even on the twist.
--
-- May incorrectly return 0 with negligible chance if the mask happens to match
-- the masked key. I haven't checked if clamping prevents that from happening.
--
local function exchange(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    return exchangeOnPoint(sk, c25.decode(pk))
end

--- Performs an exchange against an Ed25519 key.
--
-- This is done by converting the key into X25519 before passing it to the
-- regular exchange. Using this function on the result of @{signaturePk} leads
-- to the same value as using @{exchange} on the result of @{exchangePk}.
--
local function exchangeEd(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    return exchangeOnPoint(sk, c25.decodeEd(pk))
end

--- Signs a message using Ed25519.
local function sign(sk, pk, msg)
    expect(1, sk, "string")
    assert(#sk == 64, "masked secret key length must be 64")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    expect(3, msg, "string")

    -- Secret key.
    local xr = fq.decode(sk:sub(1, 32))
    local r = fq.decodeClamped(sk:sub(33))

    -- Commitment.
    local k = fq.decodeWide(random.random(64))
    local rStr = ed.encode(ed.mulG(fq.bits(k)))

    -- Challenge.
    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    -- Response.
    local s = fq.add(fq.add(k, fq.mul(xr, e)), fq.mul(r, e))
    local sStr = fq.encode(s)

    return rStr .. sStr
end

return {
    maskExchangeSk = maskExchangeSk,
    maskSignatureSk = maskSignatureSk,
    remask = remask,
    exchangePk = exchangePk,
    exchangeEsk = exchangeEsk,
    signaturePk = signaturePk,
    exchange = exchange,
    exchangeEd = exchangeEd,
    sign = sign,
}
