--- The SHA256 cryptographic hash function.
--
-- @module sha256
--

local expect  = require "cc.expect".expect
local packing = require "ccryptolib.internal.packing"

local rol = bit32.lrotate
local shr = bit32.rshift
local bxor = bit32.bxor
local bnot = bit32.bnot
local band = bit32.band
local unpack = unpack or table.unpack
local p1x8, fmt1x8 = packing.compilePack(">I8")
local p16x4, fmt16x4 = packing.compilePack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)
local p8x4, fmt8x4 = packing.compilePack(">I4I4I4I4I4I4I4I4")
local u8x4 = packing.compileUnpack(fmt8x4)

local function primes(n, exp)
    local out = {}
    local p = 2
    for i = 1, n do
        out[i] = bxor(p ^ exp % 1 * 2 ^ 32)
        repeat p = p + 1 until 2 ^ p % p == 2
    end
    return out
end

local K = primes(64, 1 / 3)

local h0 = primes(8, 1 / 2)

local function compress(h, w)
    local h0, h1, h2, h3, h4, h5, h6, h7 = unpack(h)
    local K = K

    -- Message schedule.
    for j = 17, 64 do
        local wf = w[j - 15]
        local w2 = w[j - 2]
        local s0 = bxor(rol(wf, 25), rol(wf, 14), shr(wf, 3))
        local s1 = bxor(rol(w2, 15), rol(w2, 13), shr(w2, 10))
        w[j] = w[j - 16] + s0 + w[j - 7] + s1
    end

    -- Block.
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for j = 1, 64 do
        local s1 = bxor(rol(e, 26), rol(e, 21), rol(e, 7))
        local ch = bxor(band(e, f), band(bnot(e), g))
        local temp1 = h + s1 + ch + K[j] + w[j]
        local s0 = bxor(rol(a, 30), rol(a, 19), rol(a, 10))
        local maj = bxor(band(a, b), band(a, c), band(b, c))
        local temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    end

    return {
        (h0 + a) % 2 ^ 32,
        (h1 + b) % 2 ^ 32,
        (h2 + c) % 2 ^ 32,
        (h3 + d) % 2 ^ 32,
        (h4 + e) % 2 ^ 32,
        (h5 + f) % 2 ^ 32,
        (h6 + g) % 2 ^ 32,
        (h7 + h) % 2 ^ 32,
    }
end

--- Hashes data using SHA256.
--
-- @tparam string data Input bytes.
-- @treturn string The 32-byte hash value.
--
local function digest(data)
    expect(1, data, "string")

    -- Pad input.
    local bitlen = #data * 8
    local padlen = -(#data + 9) % 64
    data = data .. "\x80" .. ("\0"):rep(padlen) .. p1x8(fmt1x8, bitlen)

    -- Digest.
    local h = h0
    for i = 1, #data, 64 do
        h = compress(h, {u16x4(fmt16x4, data, i)})
    end

    return p8x4(fmt8x4, unpack(h))
end

--- Hashes a password using PBKDF2-HMAC-SHA256.
--
-- @tparam password string The password to hash.
-- @tparam salt string The password's salt.
-- @tparam iter number The number of iterations to perform.
-- @treturn string The 32-byte derived key.
--
local function pbkdf2(password, salt, iter)
    expect(1, password, "string")
    expect(2, salt, "string")
    expect(3, iter, "number")
    assert(iter % 1 == 0, "iteration number must be an integer")
    assert(iter > 0, "iteration number must be positive")

    -- Pad password.
    if #password > 64 then password = digest(password) end
    password = password .. ("\0"):rep(-#password % 64)
    password = {u16x4(fmt16x4, password, 1)}

    -- Compute password blocks.
    local ikp = {}
    local okp = {}
    for i = 1, 16 do
        ikp[i] = bxor(password[i], 0x36363636)
        okp[i] = bxor(password[i], 0x5c5c5c5c)
    end

    local hikp = compress(h0, ikp)
    local hokp = compress(h0, okp)

    -- 96-byte padding.
    local pad96 = {2 ^ 31, 0, 0, 0, 0, 0, 0, 0x300}

    -- First iteration.
    local pre = p16x4(fmt16x4, unpack(ikp))
    local hs = {u8x4(fmt8x4, digest(pre .. salt .. "\0\0\0\1"), 1)}
    for i = 1, 8 do hs[i + 8] = pad96[i] end
    hs = compress(hokp, hs)

    -- Second iteration onwards.
    local out = {unpack(hs)}
    for _ = 2, iter do
        for i = 1, 8 do hs[i + 8] = pad96[i] end
        hs = compress(hikp, hs)
        for i = 1, 8 do hs[i + 8] = pad96[i] end
        hs = compress(hokp, hs)
        for i = 1, 8 do out[i] = bxor(out[i], hs[i]) end
    end

    return p8x4(fmt8x4, unpack(out))
end

return {
    digest = digest,
    pbkdf2 = pbkdf2,
}
