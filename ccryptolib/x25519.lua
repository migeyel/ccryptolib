--- The X25519 key exchange scheme.
--
-- @module x25519
--

local expect = require "cc.expect".expect
local util   = require "ccryptolib.internal.util"
local c25    = require "ccryptolib.internal.curve25519"

local mod = {}

--- Computes the public key from a secret key.
--
-- @tparam string sk A random 32-byte secret key.
-- @treturn string The matching public key.
--
function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    return c25.encode(c25.scale(c25.mulG(util.bits(sk))))
end

--- Performs the key exchange.
--
-- @tparam string sk A secret key.
-- @tparam string pk A public key, usually derived from a second secret key.
-- @treturn string The 32-byte shared secret between both keys.
--
function mod.exchange(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    return c25.encode(c25.scale(c25.ladder8(c25.decode(pk), util.bits8(sk))))
end

return mod
