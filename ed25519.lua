--- The Ed25519 digital signature scheme.
--
-- **Note:** This library is provided for compatibility and provides no side
-- channel resistance by itself.
--
-- @module ed25519
--

local expect  = require "cc.expect".expect
local fq      = require "ccryptolib.internal.fq"
local ed25519 = require "ccryptolib.internal.ed25519"
local sha512  = require "ccryptolib.internal.sha512"

local mod = {}

--- Computes a public key from a secret key.
--
-- @tparam string sk A random 32-byte secret key.
-- @treturn string The matching 32-byte public key.
--
function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    local h = sha512.digest(sk)
    local x = fq.decodeClamped(h:sub(1, 32))

    return ed25519.encode(ed25519.scale(ed25519.mulG(fq.bits(x))))
end

--- Signs a message.
--
-- @tparam string sk The signer's secret key.
-- @tparam string pk The signer's public key.
-- @tparam string msg The message to be signed.
-- @treturn string The 64-byte signature on the message.
--
function mod.sign(sk, pk, msg)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    expect(3, msg, "string")

    -- Secret key.
    local h = sha512.digest(sk)
    local x = fq.decodeClamped(h:sub(1, 32))

    -- Commitment.
    local k = fq.decodeWide(sha512.digest(h:sub(33) .. msg))
    local r = ed25519.mulG(fq.bits(k))
    local rStr = ed25519.encode(ed25519.scale(r))

    -- Challenge.
    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    -- Response.
    local s = fq.add(k, fq.neg(fq.mul(x, e)))
    local sStr = fq.encode(s)

    return rStr .. sStr
end

--- Verifies a signature on a message.
--
-- @tparam string pk The signer's public key.
-- @tparam string msg The signed message.
-- @tparam string sig The signature.
-- @treturn boolean Whether the signature is valid or not.
--
function mod.verify(pk, msg, sig)
    expect(1, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    expect(2, msg, "string")
    expect(3, sig, "string")
    assert(#sig == 64, "signature length must be 64")

    local y = ed25519.decode(pk)
    if not y then return nil end

    local rStr = sig:sub(1, 32)
    local sStr = sig:sub(33)

    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    local gs = ed25519.mulG(fq.bits(fq.decode(sStr)))
    local ye = ed25519.mul(y, fq.bits(e))
    local rv = ed25519.add(gs, ed25519.niels(ye))

    return ed25519.encode(ed25519.scale(rv)) == rStr
end

return mod
