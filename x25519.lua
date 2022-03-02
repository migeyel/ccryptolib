local expect = require "cc.expect".expect
local fp     = require "ccryptolib.internal.fp"
local x25519 = require "ccryptolib.internal.x25519"

local mod = {}

function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return fp.encode(x25519.ladder(x25519.G, x25519.bits(sk)))
end

function mod.exchange(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")

    return fp.encode(x25519.ladder(fp.decode(pk), x25519.bits(sk)))
end

return mod
