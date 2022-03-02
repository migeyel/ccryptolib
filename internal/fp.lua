local unpack = unpack or table.unpack

local function num(n)
    return {n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
end

local function add(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
    return {
        a00 + b00,
        a01 + b01,
        a02 + b02,
        a03 + b03,
        a04 + b04,
        a05 + b05,
        a06 + b06,
        a07 + b07,
        a08 + b08,
        a09 + b09,
        a10 + b10,
        a11 + b11,
    }
end

local function sub(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
    return {
        a00 - b00,
        a01 - b01,
        a02 - b02,
        a03 - b03,
        a04 - b04,
        a05 - b05,
        a06 - b06,
        a07 - b07,
        a08 - b08,
        a09 - b09,
        a10 - b10,
        a11 - b11,
    }
end

local function kmul(a, k)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local c00, c01, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11

    -- Multiply.
    c00 = a00 * k
    c01 = a01 * k
    c02 = a02 * k
    c03 = a03 * k
    c04 = a04 * k
    c05 = a05 * k
    c06 = a06 * k
    c07 = a07 * k
    c08 = a08 * k
    c09 = a09 * k
    c10 = a10 * k
    c11 = a11 * k

    -- Carry and reduce.
    a11 = c11 % 2 ^ 255 c00 = c00 + (c11 - a11) * (19 / 2 ^ 255)

    a00 = c00 % 2 ^ 22  c01 = c01 + (c00 - a00)
    a01 = c01 % 2 ^ 43  c02 = c02 + (c01 - a01)
    a02 = c02 % 2 ^ 64  c03 = c03 + (c02 - a02)
    a03 = c03 % 2 ^ 85  c04 = c04 + (c03 - a03)
    a04 = c04 % 2 ^ 107 c05 = c05 + (c04 - a04)
    a05 = c05 % 2 ^ 128 c06 = c06 + (c05 - a05)
    a06 = c06 % 2 ^ 149 c07 = c07 + (c06 - a06)
    a07 = c07 % 2 ^ 170 c08 = c08 + (c07 - a07)
    a08 = c08 % 2 ^ 192 c09 = c09 + (c08 - a08)
    a09 = c09 % 2 ^ 213 c10 = c10 + (c09 - a09)
    a10 = c10 % 2 ^ 234 c11 = a11 + (c10 - a10)

    a11 = c11 % 2 ^ 255 a00 = a00 + (c11 - a11) * (19 / 2 ^ 255)

    return {a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11}
end

local function mul(a, b)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 = unpack(b)
    local c00, c01, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11

    -- Multiply high half.
    c00 = a11 * b01
        + a10 * b02
        + a09 * b03
        + a08 * b04
        + a07 * b05
        + a06 * b06
        + a05 * b07
        + a04 * b08
        + a03 * b09
        + a02 * b10
        + a01 * b11
    c01 = a11 * b02
        + a10 * b03
        + a09 * b04
        + a08 * b05
        + a07 * b06
        + a06 * b07
        + a05 * b08
        + a04 * b09
        + a03 * b10
        + a02 * b11
    c02 = a11 * b03
        + a10 * b04
        + a09 * b05
        + a08 * b06
        + a07 * b07
        + a06 * b08
        + a05 * b09
        + a04 * b10
        + a03 * b11
    c03 = a11 * b04
        + a10 * b05
        + a09 * b06
        + a08 * b07
        + a07 * b08
        + a06 * b09
        + a05 * b10
        + a04 * b11
    c04 = a11 * b05
        + a10 * b06
        + a09 * b07
        + a08 * b08
        + a07 * b09
        + a06 * b10
        + a05 * b11
    c05 = a11 * b06
        + a10 * b07
        + a09 * b08
        + a08 * b09
        + a07 * b10
        + a06 * b11
    c06 = a11 * b07
        + a10 * b08
        + a09 * b09
        + a08 * b10
        + a07 * b11
    c07 = a11 * b08
        + a10 * b09
        + a09 * b10
        + a08 * b11
    c08 = a11 * b09
        + a10 * b10
        + a09 * b11
    c09 = a11 * b10
        + a10 * b11
    c10 = a11 * b11

    -- Multiply low half with reduction.
    c00 = c00 * (19 / 2 ^ 255)
        + a00 * b00
    c01 = c01 * (19 / 2 ^ 255)
        + a01 * b00
        + a00 * b01
    c02 = c02 * (19 / 2 ^ 255)
        + a02 * b00
        + a01 * b01
        + a00 * b02
    c03 = c03 * (19 / 2 ^ 255)
        + a03 * b00
        + a02 * b01
        + a01 * b02
        + a00 * b03
    c04 = c04 * (19 / 2 ^ 255)
        + a04 * b00
        + a03 * b01
        + a02 * b02
        + a01 * b03
        + a00 * b04
    c05 = c05 * (19 / 2 ^ 255)
        + a05 * b00
        + a04 * b01
        + a03 * b02
        + a02 * b03
        + a01 * b04
        + a00 * b05
    c06 = c06 * (19 / 2 ^ 255)
        + a06 * b00
        + a05 * b01
        + a04 * b02
        + a03 * b03
        + a02 * b04
        + a01 * b05
        + a00 * b06
    c07 = c07 * (19 / 2 ^ 255)
        + a07 * b00
        + a06 * b01
        + a05 * b02
        + a04 * b03
        + a03 * b04
        + a02 * b05
        + a01 * b06
        + a00 * b07
    c08 = c08 * (19 / 2 ^ 255)
        + a08 * b00
        + a07 * b01
        + a06 * b02
        + a05 * b03
        + a04 * b04
        + a03 * b05
        + a02 * b06
        + a01 * b07
        + a00 * b08
    c09 = c09 * (19 / 2 ^ 255)
        + a09 * b00
        + a08 * b01
        + a07 * b02
        + a06 * b03
        + a05 * b04
        + a04 * b05
        + a03 * b06
        + a02 * b07
        + a01 * b08
        + a00 * b09
    c10 = c10 * (19 / 2 ^ 255)
        + a10 * b00
        + a09 * b01
        + a08 * b02
        + a07 * b03
        + a06 * b04
        + a05 * b05
        + a04 * b06
        + a03 * b07
        + a02 * b08
        + a01 * b09
        + a00 * b10
    c11 = a11 * b00
        + a10 * b01
        + a09 * b02
        + a08 * b03
        + a07 * b04
        + a06 * b05
        + a05 * b06
        + a04 * b07
        + a03 * b08
        + a02 * b09
        + a01 * b10
        + a00 * b11

    -- Carry and reduce.
    a10 = c10 % 2 ^ 234 c11 = c11 + (c10 - a10)
    a11 = c11 % 2 ^ 255 c00 = c00 + (c11 - a11) * (19 / 2 ^ 255)

    a00 = c00 % 2 ^ 22  c01 = c01 + (c00 - a00)
    a01 = c01 % 2 ^ 43  c02 = c02 + (c01 - a01)
    a02 = c02 % 2 ^ 64  c03 = c03 + (c02 - a02)
    a03 = c03 % 2 ^ 85  c04 = c04 + (c03 - a03)
    a04 = c04 % 2 ^ 107 c05 = c05 + (c04 - a04)
    a05 = c05 % 2 ^ 128 c06 = c06 + (c05 - a05)
    a06 = c06 % 2 ^ 149 c07 = c07 + (c06 - a06)
    a07 = c07 % 2 ^ 170 c08 = c08 + (c07 - a07)
    a08 = c08 % 2 ^ 192 c09 = c09 + (c08 - a08)
    a09 = c09 % 2 ^ 213 c10 = a10 + (c09 - a09)
    a10 = c10 % 2 ^ 234 c11 = a11 + (c10 - a10)

    a11 = c11 % 2 ^ 255 a00 = a00 + (c11 - a11) * (19 / 2 ^ 255)

    return {a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11}
end

local function square(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)
    local d00, d01, d02, d03, d04, d05, d06, d07, d08, d09, d10
    local c00, c01, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11

    -- Compute 2a.
    d00 = a00 + a00
    d01 = a01 + a01
    d02 = a02 + a02
    d03 = a03 + a03
    d04 = a04 + a04
    d05 = a05 + a05
    d06 = a06 + a06
    d07 = a07 + a07
    d08 = a08 + a08
    d09 = a09 + a09
    d10 = a10 + a10

    -- Multiply high half.
    c00 = a11 * d01
        + a10 * d02
        + a09 * d03
        + a08 * d04
        + a07 * d05
        + a06 * a06
    c01 = a11 * d02
        + a10 * d03
        + a09 * d04
        + a08 * d05
        + a07 * d06
    c02 = a11 * d03
        + a10 * d04
        + a09 * d05
        + a08 * d06
        + a07 * a07
    c03 = a11 * d04
        + a10 * d05
        + a09 * d06
        + a08 * d07
    c04 = a11 * d05
        + a10 * d06
        + a09 * d07
        + a08 * a08
    c05 = a11 * d06
        + a10 * d07
        + a09 * d08
    c06 = a11 * d07
        + a10 * d08
        + a09 * a09
    c07 = a11 * d08
        + a10 * d09
    c08 = a11 * d09
        + a10 * a10
    c09 = a11 * d10
    c10 = a11 * a11

    -- Multiply low half with reduction.
    c00 = c00 * (19 / 2 ^ 255)
        + a00 * a00
    c01 = c01 * (19 / 2 ^ 255)
        + a01 * d00
    c02 = c02 * (19 / 2 ^ 255)
        + a02 * d00
        + a01 * a01
    c03 = c03 * (19 / 2 ^ 255)
        + a03 * d00
        + a02 * d01
    c04 = c04 * (19 / 2 ^ 255)
        + a04 * d00
        + a03 * d01
        + a02 * a02
    c05 = c05 * (19 / 2 ^ 255)
        + a05 * d00
        + a04 * d01
        + a03 * d02
    c06 = c06 * (19 / 2 ^ 255)
        + a06 * d00
        + a05 * d01
        + a04 * d02
        + a03 * a03
    c07 = c07 * (19 / 2 ^ 255)
        + a07 * d00
        + a06 * d01
        + a05 * d02
        + a04 * d03
    c08 = c08 * (19 / 2 ^ 255)
        + a08 * d00
        + a07 * d01
        + a06 * d02
        + a05 * d03
        + a04 * a04
    c09 = c09 * (19 / 2 ^ 255)
        + a09 * d00
        + a08 * d01
        + a07 * d02
        + a06 * d03
        + a05 * d04
    c10 = c10 * (19 / 2 ^ 255)
        + a10 * d00
        + a09 * d01
        + a08 * d02
        + a07 * d03
        + a06 * d04
        + a05 * a05
    c11 = a11 * d00
        + a10 * d01
        + a09 * d02
        + a08 * d03
        + a07 * d04
        + a06 * d05

    -- Carry and reduce.
    a10 = c10 % 2 ^ 234 c11 = c11 + (c10 - a10)
    a11 = c11 % 2 ^ 255 c00 = c00 + (c11 - a11) * (19 / 2 ^ 255)

    a00 = c00 % 2 ^ 22  c01 = c01 + (c00 - a00)
    a01 = c01 % 2 ^ 43  c02 = c02 + (c01 - a01)
    a02 = c02 % 2 ^ 64  c03 = c03 + (c02 - a02)
    a03 = c03 % 2 ^ 85  c04 = c04 + (c03 - a03)
    a04 = c04 % 2 ^ 107 c05 = c05 + (c04 - a04)
    a05 = c05 % 2 ^ 128 c06 = c06 + (c05 - a05)
    a06 = c06 % 2 ^ 149 c07 = c07 + (c06 - a06)
    a07 = c07 % 2 ^ 170 c08 = c08 + (c07 - a07)
    a08 = c08 % 2 ^ 192 c09 = c09 + (c08 - a08)
    a09 = c09 % 2 ^ 213 c10 = a10 + (c09 - a09)
    a10 = c10 % 2 ^ 234 c11 = a11 + (c10 - a10)

    a11 = c11 % 2 ^ 255 a00 = a00 + (c11 - a11) * (19 / 2 ^ 255)

    return {a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11}
end

local function nsquare(a, n)
    for _ = 1, n do a = square(a) end
    return a
end

local function invert(a)
    local a2 = square(a)
    local a9 = mul(a, nsquare(a2, 2))
    local a11 = mul(a9, a2)
    local x5 = mul(square(a11), a9)
    local x10 = mul(nsquare(x5, 5), x5)
    local x20 = mul(nsquare(x10, 10), x10)
    local x40 = mul(nsquare(x20, 20), x20)
    local x50 = mul(nsquare(x40, 10), x10)
    local x100 = mul(nsquare(x50, 50), x50)
    local x200 = mul(nsquare(x100, 100), x100)
    local x250 = mul(nsquare(x200, 50), x50)
    return mul(nsquare(x250, 5), a11)
end

local function encode(a)
    local a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 = unpack(a)

    -- Canonicalize.
    if      a11 == (2 ^ 21 - 1) * 2 ^ 234
        and a10 == (2 ^ 21 - 1) * 2 ^ 213
        and a09 == (2 ^ 21 - 1) * 2 ^ 192
        and a08 == (2 ^ 22 - 1) * 2 ^ 170
        and a07 == (2 ^ 21 - 1) * 2 ^ 149
        and a06 == (2 ^ 21 - 1) * 2 ^ 128
        and a05 == (2 ^ 21 - 1) * 2 ^ 107
        and a04 == (2 ^ 22 - 1) * 2 ^ 85
        and a03 == (2 ^ 21 - 1) * 2 ^ 64
        and a02 == (2 ^ 21 - 1) * 2 ^ 43
        and a01 == (2 ^ 21 - 1) * 2 ^ 22
        and a00 >= 2 ^ 22 - 19
    then
        a11 = 0
        a10 = 0
        a09 = 0
        a08 = 0
        a07 = 0
        a06 = 0
        a05 = 0
        a04 = 0
        a03 = 0
        a02 = 0
        a01 = 0
        a00 = a00 - (2 ^ 22 - 19)
    end

    -- Encode.
    -- TODO this can be improved.
    local bytes = {}
    local acc = a00
    local function putBytes(n)
        for _ = 1, n do
            local byte = acc % 256
            bytes[#bytes + 1] = byte
            acc = (acc - byte) / 256
        end
    end

    putBytes(2) acc = acc + a01 / 2 ^ 16
    putBytes(3) acc = acc + a02 / 2 ^ 40
    putBytes(3) acc = acc + a03 / 2 ^ 64
    putBytes(2) acc = acc + a04 / 2 ^ 80
    putBytes(3) acc = acc + a05 / 2 ^ 104
    putBytes(3) acc = acc + a06 / 2 ^ 128
    putBytes(2) acc = acc + a07 / 2 ^ 144
    putBytes(3) acc = acc + a08 / 2 ^ 168
    putBytes(3) acc = acc + a09 / 2 ^ 192
    putBytes(2) acc = acc + a10 / 2 ^ 208
    putBytes(3) acc = acc + a11 / 2 ^ 232
    putBytes(3)

    return string.char(unpack(bytes))
end

local function decode(b)
    local w00, w01, w02, w03, w04, w05, w06, w07, w08, w09, w10, w11 =
        ("<I3I3I2I3I3I2I3I3I2I3I3I2"):unpack(b)

    w11 = w11 % 2 ^ 15

    local out = {
        w00,
        w01 * 2 ^ 24,
        w02 * 2 ^ 48,
        w03 * 2 ^ 64,
        w04 * 2 ^ 88,
        w05 * 2 ^ 112,
        w06 * 2 ^ 128,
        w07 * 2 ^ 152,
        w08 * 2 ^ 176,
        w09 * 2 ^ 192,
        w10 * 2 ^ 216,
        w11 * 2 ^ 240,
    }

    return kmul(out, 1)
end

return {
    num = num,
    add = add,
    sub = sub,
    kmul = kmul,
    mul = mul,
    square = square,
    invert = invert,
    encode = encode,
    decode = decode,
}
