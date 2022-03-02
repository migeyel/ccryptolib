local expect = require "cc.expect".expect
local fp     = require "ccryptolib.internal.fp"
local x25519 = require "ccryptolib.internal.x25519"

local unpack = unpack or table.unpack

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

local function ladder8(dx, bits)
    local x1 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    local z1 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    local x2, z2 = dx, x1

    -- Standard ladder.
    for i = #bits, 1, -1 do
        if bits[i] == 0 then
            x1, z1, x2, z2 = x25519.step(dx, x1, z1, x2, z2)
        else
            x2, z2, x1, z1 = x25519.step(dx, x2, z2, x1, z1)
        end
    end

    -- Multiply by 8 (double 3 times).
    for _ = 1, 3 do
        x1, z1 = x25519.double(x1, z1)
    end

    return fp.mul(x1, fp.invert(z1))
end

local mod = {}

function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return fp.encode(ladder8(x25519.G, bits(sk)))
end

function mod.exchange(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")

    return fp.encode(ladder8(fp.decode(pk), bits(sk)))
end

return mod
