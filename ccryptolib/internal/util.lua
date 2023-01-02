--- Converts a little-endian array from one power-of-two base to another.
--
-- @tparam {number...} a The array to convert, in little-endian.
-- @tparam number base1 The base to convert from. Must be a power of 2.
-- @tparam number base2 The base to convert to. Must be a power of 2.
-- @treturn {number...}
--
local function rebaseLE(a, base1, base2) -- TODO Write contract properly.
    local out = {}
    local outlen = 1
    local acc = 0
    local mul = 1
    for i = 1, #a do
        acc = acc + a[i] * mul
        mul = mul * base1
        while mul >= base2 do
            local rem = acc % base2
            acc = (acc - rem) / base2
            mul = mul / base2
            out[outlen] = rem
            outlen = outlen + 1
        end
    end
    if mul > 0 then
        out[outlen] = acc
    end
    return out
end

--- Decodes bits with X25519/Ed25519 exponent clamping.
--
-- @taparm string str The 32-byte encoded exponent.
-- @treturn {number...} The decoded clamped bits.
--
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
    out[255] = 1
    out[256] = 0

    return out
end

--- Decodes bits with X25519/Ed25519 exponent clamping and division by 8.
--
-- @taparm string str The 32-byte encoded exponent.
-- @treturn {number...} The decoded clamped bits, divided by 8.
--
local function bits8(str)
    return {unpack(bits(str), 4)}
end

return {
    rebaseLE = rebaseLE,
    bits = bits,
    bits8 = bits8,
}
