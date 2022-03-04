local expect = require "cc.expect".expect
local fp     = require "ccryptolib.internal.fp"
local fq     = require "ccryptolib.internal.fq"
local x25519 = require "ccryptolib.internal.x25519"
local maddq  = require "ccryptolib.internal.maddq"
local random = require "ccryptolib.random"

local ORDER = 4

--- The inverse of 8 modulo q (in montgomery form).
local INV8Q = {
    5110253,
    3039345,
    2503500,
    11779568,
    15416472,
    16766550,
    16777215,
    16777215,
    16777215,
    16777215,
    4095,
}

local function ladder8(dx, bits)
    local x1 = fp.num(1)
    local z1 = fp.num(0)

    -- Compute a randomization factor for randomized projective coordinates.
    -- Biased but good enough.
    local rf = fp.decode(random.random(32))

    local x2 = fp.mul(rf, dx)
    local z2 = rf

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

function mod.new(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return maddq.new(fq.decodeClamped(sk), ORDER)
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

function mod.exchange(sks, pk, mc)
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    expect(3, mc, "string")
    assert(#mc == 32, "multiplier length must be 32")

    -- Reduce secret key using the multiplier.
    local skmc = maddq.unwrap(maddq.mul(sks, fq.decodeClamped(mc)))

    -- Get bits.
    -- We have our exponent modulo q. We also know that its value is 0 modulo 8.
    -- Use the Chinese Remainder Theorem to find its value modulo 8q.
    local bits = fq.bits(fq.mul(skmc, INV8Q))

    return fp.encode(ladder8(fp.decode(pk), bits))
end

return mod
