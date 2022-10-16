--- High-performance binary packing of integers.
--
-- :::note Internal Module
-- This module is meant for internal use within the library. Its API is unstable
-- and subject to change without major version bumps.
-- :::
--
-- <br />
--
-- :::warning
-- For performance reasons, **the generated functions do not check types,
-- lengths, nor ranges**. You must ensure that the passed arguments are
-- well-formed and respect the format string yourself.
-- :::
--
-- <br />
--
-- @module[kind=internal] internal.packing
--

local fmt = string.format

local function mkPack(words, BE)
    local out = "local C=string.char return function(_,"
    local nb = 0
    for i = 1, #words do
        out = out .. fmt("n%d,", i)
        nb = nb + words[i]
    end
    out = out:sub(1, -2) .. ")local "
    for i = 1, nb do
        out = out .. fmt("b%d,", i)
    end
    out = out:sub(1, -2) .. " "
    local bi = 1
    for i = 1, #words do
        for _ = 1, words[i] - 1 do
            out = out .. fmt("b%d=n%d%%2^8 n%d=(n%d-b%d)*2^-8 ", bi, i, i, i, bi)
            bi = bi + 1
        end
        bi = bi + 1
    end
    out = out .. "return C("
    bi = 1
    if not BE then
        for i = 1, #words do
            for _ = 1, words[i] - 1 do
                out = out .. fmt("b%d,", bi)
                bi = bi + 1
            end
            out = out .. fmt("n%d%%2^8,", i)
            bi = bi + 1
        end
    else
        for i = 1, #words do
            out = out .. fmt("n%d%%2^8,", i)
            bi = bi + words[i] - 2
            for _ = 1, words[i] - 1 do
                out = out .. fmt("b%d,", bi)
                bi = bi - 1
            end
            bi = bi + words[i] + 1
        end
    end
    out = out:sub(1, -2) .. ")end"
    return load(out)()
end

local function mkUnpack(words, BE)
    local out = "local B=string.byte return function(_,s,i)local "
    local bi = 1
    if not BE then
        for i = 1, #words do
            for _ = 1, words[i] do
                out = out .. fmt("b%d,", bi)
                bi = bi + 1
            end
        end
    else
        for i = 1, #words do
            bi = bi + words[i] - 1
            for _ = 1, words[i] do
                out = out .. fmt("b%d,", bi)
                bi = bi - 1
            end
            bi = bi + words[i] + 1
        end
    end
    out = out:sub(1, -2) .. fmt("=B(s,i,i+%d)return ", bi - 2)
    bi = 1
    for i = 1, #words do
        out = out .. fmt("b%d", bi)
        bi = bi + 1
        for j = 2, words[i] do
            out = out .. fmt("+b%d*2^%d", bi, 8 * j - 8)
            bi = bi + 1
        end
        out = out .. ","
    end
    out = out .. fmt("i+%d end", bi - 1)
    return load(out)()
end

local mod = {}

-- Check whether string.pack is implemented in a high-speed language.
if not string.pack or pcall(string.dump, string.pack) then
    local function compile(fmt, fn)
        local e = assert(fmt:match("^([><])I[I%d]+$"), "invalid format string")
        local w = {}
        for i in fmt:gmatch("I([%d]+)") do
            local n = tonumber(i) or 4
            assert(n > 0 and n <= 4, "integral size out of limits")
            w[#w + 1] = n
        end
        return fn(w, e == ">")
    end

    local packCache = {}
    local unpackCache = {}

    --- (`string.pack == nil`) Compiles a binary packing function.
    -- @tparam string fmt A string matched by `^([><])I[I%d]+$`.
    -- @treturn function A high-performance function that behaves like an unsafe
    -- version of `string.pack` for the given format string. Note that the third
    -- argument isn't optional.
    -- @treturn string fmt
    -- @throws If the string is invalid or has an invalid integral size.
    -- @throws If the compiled function is too large.
    function mod.compilePack(fmt)
        if not packCache[fmt] then
            packCache[fmt] = compile(fmt, mkPack)
        end
        return packCache[fmt], fmt
    end

    --- (`string.pack == nil`) Compiles a binary unpacking function.
    -- @tparam string fmt A string matched by `^([><])I[I%d]+$`.
    -- @treturn function A high-performance function that behaves like an unsafe
    -- version of `string.unpack` for the given format string.
    -- @treturn string fmt
    -- @throws If the string is invalid or has an invalid integral size.
    -- @throws If the compiled function is too large.
    function mod.compileUnpack(fmt)
        if not unpackCache[fmt] then
            unpackCache[fmt] = compile(fmt, mkUnpack)
        end
        return unpackCache[fmt], fmt
    end

    return mod
else
    --- (`string.pack ~= nil`) Compiles a binary packing function.
    -- @tparam string fmt
    -- @treturn function `string.pack`
    -- @treturn string fmt
    mod.compilePack = function(fmt) return string.pack, fmt end

    --- (`string.pack ~= nil`) Compiles a binary unpacking function.
    -- @tparam string fmt
    -- @treturn function `string.unpack`
    -- @treturn string fmt
    mod.compileUnpack = function(fmt) return string.unpack, fmt end
end

return mod
