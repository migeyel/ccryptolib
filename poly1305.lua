--- The Poly1305 one-time authenticator.
--
-- @module poly1305
--

local expect = require "cc.expect".expect

local band = bit32.band

local mod = {}

--- Computes a Poly1305 message authentication code.
--
-- @tparam string key A 32-byte single-use random key.
-- @tparam string message The message to authenticate.
-- @treturn string The 16-byte authentication tag.
--
function mod.mac(key, message)
    expect(1, key, "string")
    assert(#key == 32, "key length must be 32")
    expect(2, message, "string")

    -- Pad message.
    local pbplen = #message - 15
    if #message % 16 ~= 0 then
        message = message .. "\1"
        message = message .. ("\0"):rep(-#message % 16)
    end

    -- Decode r.
    local r0, t1, r2, r3, t4, r5 = ("<I3I3I2I3I3I2"):unpack(key)

    -- Clamp and shift.
    t1 = band(t1, 0xfffc0f) * 2 ^ 24
    r2 = band(r2, 0x000fff) * 2 ^ 48
    r3 = band(r3, 0xfffffc) * 2 ^ 64
    t4 = band(t4, 0xfffc0f) * 2 ^ 88
    r5 = band(r5, 0x000fff) * 2 ^ 112

    -- Split some words to fit.
    local r1 = t1 % 2 ^ 44  r2 = r2 + (t1 - r1)
    local r4 = t4 % 2 ^ 109 r5 = r5 + (t4 - r4)

    -- Digest.
    local h0, h1, h2, h3, h4, h5 = 0, 0, 0, 0, 0, 0
    for i = 1, #message, 16 do
        -- Decode message block.
        local m0, m1, m2, m3, m4, m5 = ("<I3I3I3I2I3I2"):unpack(message, i)

        -- Shift and add to accumulator.
        h0 = h0 + m0
        h1 = h1 + m1 * 2 ^ 24
        h2 = h2 + m2 * 2 ^ 48
        h3 = h3 + m3 * 2 ^ 72
        h4 = h4 + m4 * 2 ^ 88
        h5 = h5 + m5 * 2 ^ 112

        -- Apply per-block padding when applicable.
        if i <= pbplen then
            h5 = h5 + 2 ^ 128
        end

        -- Multiply accumulator by r.
        local g00 = h0 * r0
        local g01 = h1 * r0 + h0 * r1
        local g02 = h2 * r0 + h1 * r1 + h0 * r2
        local g03 = h3 * r0 + h2 * r1 + h1 * r2 + h0 * r3
        local g04 = h4 * r0 + h3 * r1 + h2 * r2 + h1 * r3 + h0 * r4
        local g05 = h5 * r0 + h4 * r1 + h3 * r2 + h2 * r3 + h1 * r4 + h0 * r5
        local g06 = h5 * r1 + h4 * r2 + h3 * r3 + h2 * r4 + h1 * r5
        local g07 = h5 * r2 + h4 * r3 + h3 * r4 + h2 * r5
        local g08 = h5 * r3 + h4 * r4 + h3 * r5
        local g09 = h5 * r4 + h4 * r5
        local g10 = h5 * r5

        -- Carry and reduce.
        h5 = g05 % 2 ^ 130 g06 = g06 + (g05 - h5)

        g00 = g00 + g06 * (5 / 2 ^ 130)
        g01 = g01 + g07 * (5 / 2 ^ 130)
        g02 = g02 + g08 * (5 / 2 ^ 130)
        g03 = g03 + g09 * (5 / 2 ^ 130)
        g04 = g04 + g10 * (5 / 2 ^ 130)

        h0 = g00 % 2 ^ 22  g01 = g01 + (g00 - h0)
        h1 = g01 % 2 ^ 44  g02 = g02 + (g01 - h1)
        h2 = g02 % 2 ^ 65  g03 = g03 + (g02 - h2)
        h3 = g03 % 2 ^ 87  g04 = g04 + (g03 - h3)
        h4 = g04 % 2 ^ 109 g05 = h5 + (g04 - h4)
        h5 = g05 % 2 ^ 130 h0 = h0 + (g05 - h5) * (5 / 2 ^ 130)
    end

    -- Canonicalize.
    if      h5 == (2 ^ 21 - 1) * 2 ^ 109
        and h4 == (2 ^ 22 - 1) * 2 ^ 87
        and h3 == (2 ^ 22 - 1) * 2 ^ 65
        and h2 == (2 ^ 21 - 1) * 2 ^ 44
        and h1 == (2 ^ 22 - 1) * 2 ^ 22
        and h0 >= 2 ^ 22 - 5
    then
        h5 = 0
        h4 = 0
        h3 = 0
        h2 = 0
        h1 = 0
        h0 = h0 - (2 ^ 22 - 5)
    end

    -- Decode s.
    local s0, s1, s2, s3, s4, s5 = ("<I3I3I3I2I3I2"):unpack(key, 17)

    -- Add s and carry.
    h0 = h0 + s0
    h1 = h1 + s1 * 2 ^ 24
    h2 = h2 + s2 * 2 ^ 48
    h3 = h3 + s3 * 2 ^ 72
    h4 = h4 + s4 * 2 ^ 88
    h5 = h5 + s5 * 2 ^ 112

    local t0 = h0 % 2 ^ 16  h1 = h1 + (h0 - t0)
    local t1 = h1 % 2 ^ 40  h2 = h2 + (h1 - t1)
    local t2 = h2 % 2 ^ 64  h3 = h3 + (h2 - t2)
    local t3 = h3 % 2 ^ 80  h4 = h4 + (h3 - t3)
    local t4 = h4 % 2 ^ 104 h5 = h5 + (h4 - t4)
    local t5 = h5 % 2 ^ 128

    -- Encode.
    t1 = t1 * 2 ^ -16
    t2 = t2 * 2 ^ -40
    t3 = t3 * 2 ^ -64
    t4 = t4 * 2 ^ -80
    t5 = t5 * 2 ^ -104

    return ("<I2I3I3I2I3I3"):pack(t0, t1, t2, t3, t4, t5)
end

return mod
