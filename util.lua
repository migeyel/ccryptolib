local mod = {}

--- Converts a little-endian array from one power-of-two base to another.
--
-- @tparam {number...} a The array to convert, in little-endian.
-- @tparam number base1 The base to convert from. Must be a power of 2.
-- @tparam number base2 The base to convert to. Must be a power of 2.
-- @treturn {number...}
--
function mod.rebaseLE(a, base1, base2)
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

return mod
