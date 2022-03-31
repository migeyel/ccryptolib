--- The X25519 key exchange scheme.
--
-- @module x25519
--

local expect = require "cc.expect".expect
local fp     = require "ccryptolib.internal.fp"
local mont   = require "ccryptolib.internal.curve25519"

-- TODO This function feels out of place anywhere I try putting it on.
local function bits(str)
    -- Decode.
    local bytes = {str:byte(1, 32)}
    local out = {}
    for i = 1, 32 do
        local byte = bytes[i]
        for j = -7, 0 do
            local bit = byte % 2
            out[8 * i + j] = bit
            byte = (byte - bit) / 2
        end
    end

    -- Clamp.
    out[256] = 0
    out[255] = 1

    -- We remove the 3 lowest bits since the ladder already multiplies by 8.
    return {unpack(out, 4)}
end

local mod = {}

--- Computes the public key from a secret key.
--
-- @tparam string sk A random 32-byte secret key.
-- @treturn string The matching public key.
--
function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    return fp.encode(mont.ladder8(fp.kmul, 9, bits(sk)))
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
    return fp.encode(mont.ladder8(fp.mul, fp.decode(pk), bits(sk)))
end

return mod
