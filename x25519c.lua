local expect = require "cc.expect".expect
local fq     = require "ccryptolib.internal.fq"
local util   = require "ccryptolib.internal.util"
local c25    = require "ccryptolib.internal.curve25519"
local random = require "ccryptolib.random"

local mod = {}

function mod.keypair()
    local x = random.random(32)
    local r = random.random(32)
    local X = c25.mulG(util.bits(x))
    local x8 = fq.decodeClamped8(x)
    local r8 = fq.decodeClamped8(r)
    local xr8 = fq.sub(x8, r8)
    return fq.encode(xr8), r, c25.encode(c25.scale(X))
end

function mod.remask(sk, ek)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, ek, "string")
    assert(#ek == 32, "ephemeral secret key length must be 32")
    local s = random.random(32)
    local r8 = fq.decodeClamped8(ek)
    local s8 = fq.decodeClamped8(s)
    local xr8 = fq.decode(sk)
    local xs8 = fq.add(xr8, fq.sub(r8, s8))
    return fq.encode(xs8), s
end

function mod.exchange(sk, ek, pk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, ek, "string")
    assert(#ek == 32, "ephemeral secret key length must be 32")
    expect(3, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    local P = c25.decode(pk)
    local r8 = fq.decodeClamped8(ek)
    local xr8 = fq.decode(sk)
    local ruleset = fq.makeRuleset(r8, xr8)
    local rP, xrP, dP = c25.prac(P, ruleset)
    local xP = c25.dadd(dP, rP, xrP)
    return c25.encode(c25.scale(xP)), c25.encode(c25.scale(rP))
end

return mod
