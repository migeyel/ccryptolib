local expect = require "cc.expect".expect
local fp     = require "ccryptolib.internal.fp"
local fq     = require "ccryptolib.internal.fq"
local x25519 = require "ccryptolib.internal.x25519"
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

local function fqRandom()
    return fq.decodeWide(random.random(64))
end

local function fqDecodeStd(str)
    -- Decode.
    local words = {("<I3I3I3I3I3I3I3I3I3I3I2"):unpack(str)} words[12] = nil

    -- Clamp.
    words[1] = bit32.band(words[1], 0xfffff8)
    words[11] = bit32.band(words[11], 0x7fff)
    words[11] = bit32.bor(words[11], 0x4000)

    return fq.montgomery(words)
end

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

function mod.secretKeyInit(sk)
    sk = fqDecodeStd(sk)

    -- Set up the mask.
    local sks = {}
    local sum = fq.num(0)
    for i = 1, ORDER - 1 do
        sks[i] = fqRandom()
        sum = fq.add(sum, sks[i])
    end
    sks[ORDER] = fq.add(sk, fq.neg(sum))

    return sks
end

function mod.secretKeyEncode(sks)
    local out = {}
    for i = 1, ORDER do out[i] = fq.encode(sks[i]) end
    return table.concat(out)
end

function mod.secretKeyDecode(str)
    expect(1, str, "string")
    assert(#str == ORDER * 32, ("secret key length must be %d"):format(ORDER * 32))

    local out = {}
    for i = 1, ORDER do out[i] = fq.decode(str:sub(i * 32 - 31, i * 32)) end
    return out
end

function mod.secretKeyRemask(sks)
    local sum = fq.num(0)
    local out = {}

    for i = 1, ORDER - 1 do
        local element = fqRandom()
        out[i] = fq.add(sks[i], element)
        sum = fq.add(sum, element)
    end

    out[ORDER] = fq.add(sks[ORDER], fq.neg(sum))

    return out
end

function mod.exchange(sks, pk, mc)
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")
    expect(3, mc, "string")
    assert(#mc == 32, "multiplier length must be 32")

    -- Get the multiplier in Fq.
    mc = fqDecodeStd(mc)

    -- Multiply secret key members and add them together.
    -- This unwraps into the "true" secret key times the multiplier (mod q).
    local skmt = fq.num(0)
    for i = 1, #sks do skmt = fq.add(skmt, fq.mul(sks[i], mc)) end

    -- Get bits.
    -- We have our exponent modulo q. We also know that its value is 0 modulo 8.
    -- Use the Chinese Remainder Theorem to find its value modulo 8q.
    local bits = fq.bits(fq.mul(skmt, INV8Q))

    return fp.encode(ladder8(fp.decode(pk), bits))
end

return mod
