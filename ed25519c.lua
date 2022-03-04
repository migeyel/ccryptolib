local expect  = require "cc.expect".expect
local fq      = require "ccryptolib.internal.fq"
local sha512  = require "ccryptolib.internal.sha512"
local ed25519 = require "ccryptolib.internal.ed25519"
local maddq   = require "ccryptolib.internal.maddq"
local random  = require "ccryptolib.random"

local ORDER = 4

local mod = {}

function mod.new(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return maddq.new(fq.decodeClamped(sha512.digest(sk):sub(1, 32)), ORDER)
end

function mod.encode(sks)
    return maddq.encode(sks)
end

function mod.decode(str)
    expect(1, str, "string")
    assert(#str == 128, "encoded sks length must be 128")

    return maddq.decode(str)
end

function mod.remask(sks)
    return maddq.remask(sks)
end

function mod.sign(sks, pk, msg)
    -- Commitment.
    local k = fq.decodeWide(random.random(64))
    local r = ed25519.mulG(fq.bits(k))
    local rStr = ed25519.encode(ed25519.scale(r))

    -- Challenge.
    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    -- Response.
    -- Reduce secret key using the challenge and an extra mask.
    local m = fq.decodeWide(random.random(64))
    local xme = maddq.unwrap(maddq.mul(maddq.add(sks, m), e))
    local s = fq.add(fq.add(k, fq.neg(xme)), fq.mul(m, e))
    local sStr = fq.encode(s)

    return rStr .. sStr
end

return mod
