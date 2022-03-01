local expect = require "cc.expect".expect
local fp = require "ecnet.primitives.fp"

local add = fp.add
local sub = fp.sub
local kmul = fp.kmul
local mul = fp.mul
local square = fp.square
local invert = fp.invert
local encode = fp.encode
local decode = fp.decode

local function step(dx, x1, z1, x2, z2)
    local a = add(x1, z1)
    local aa = square(a)
    local b = sub(x1, z1)
    local bb = square(b)
    local e = sub(aa, bb)
    local c = add(x2, z2)
    local d = sub(x2, z2)
    local da = mul(d, a)
    local cb = mul(c, b)
    local x4 = square(add(da, cb))
    local z4 = mul(dx, square(sub(da, cb)))
    local x3 = mul(aa, bb)
    local z3 = mul(e, add(bb, kmul(e, 121666)))
    return x3, z3, x4, z4
end

local function x25519(dx, bits)
    local x1 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    local z1 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    local x2, z2 = dx, x1

    for i = #bits, 1, -1 do
        if bits[i] == 0 then
            x1, z1, x2, z2 = step(dx, x1, z1, x2, z2)
        else
            x2, z2, x1, z1 = step(dx, x2, z2, x1, z1)
        end
    end

    return mul(x1, invert(z1))
end

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
    out[1] = 0
    out[2] = 0
    out[3] = 0
    out[256] = 0
    out[255] = 1

    return out
end

local mod = {}

function mod.publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return encode(x25519({9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bits(sk)))
end

function mod.exchange(sk, pk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    expect(2, pk, "string")
    assert(#pk == 32, "public key length must be 32")

    return encode(x25519(decode(pk), bits(sk)))
end

return mod
