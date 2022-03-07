--- The SHA256 cryptographic hash function.
--
-- @module sha256
--

local expect = require "cc.expect".expect

local rol = bit32.lrotate
local shr = bit32.rshift
local bxor = bit32.bxor
local bnot = bit32.bnot
local band = bit32.band

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

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
    data = data .. "\x80" .. ("\0"):rep(padlen) .. (">I8"):pack(bitlen)

    -- Initialize state.
    local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    -- Digest.
    for i = 1, #data, 64 do
        local w = {(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4"):unpack(data, i)}

        -- Message schedule.
        for j = 17, 64 do
            local wf = w[j - 15]
            local w2 = w[j - 2]
            local s0 = bxor(rol(wf, 25), rol(wf, 14), shr(wf, 3))
            local s1 = bxor(rol(w2, 15), rol(w2, 13), shr(w2, 10))
            w[j] = w[j - 16] + s0 + w[j - 7] + s1
        end

        -- Block function.
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

        h0 = (h0 + a) % 2 ^ 32
        h1 = (h1 + b) % 2 ^ 32
        h2 = (h2 + c) % 2 ^ 32
        h3 = (h3 + d) % 2 ^ 32
        h4 = (h4 + e) % 2 ^ 32
        h5 = (h5 + f) % 2 ^ 32
        h6 = (h6 + g) % 2 ^ 32
        h7 = (h7 + h) % 2 ^ 32
    end

    return (">I4I4I4I4I4I4I4I4"):pack(h0, h1, h2, h3, h4, h5, h6, h7)
end

return {
    digest = digest,
}
