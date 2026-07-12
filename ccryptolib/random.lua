local expect = require "cc.expect".expect
local hw = require "ccryptolib.internal.hw"
local blake3 = require "ccryptolib.blake3"
local chacha20 = require "ccryptolib.chacha20"
local util = require "ccryptolib.internal.util"

local lassert = util.lassert

-- Extract local context.
local ctx = {
    "ccryptolib 2023-04-11T19:43Z random.lua initialization context",
    os.epoch("utc"),
    os.day(),
    os.time(),
    math.random(0, 2 ^ 24 - 1),
    math.random(0, 2 ^ 24 - 1),
    tostring({}),
    tostring({}),
}

local state = blake3.digest(table.concat(ctx, "|"))
local initialized = false
local hwMixed = false

--- Mixes random bytes taken by the last compatible peripheral we interacted
--- with, if any.
---
--- takeSeed resets to nil once called, so this function only does work when a
--- peripheral is (re-)attached.
local function mixHwSeed()
    local seed = hw.takeSeed()
    if not seed then return end
    state = blake3.digestKeyed(state, seed)
    hwMixed = true
end

--- Mixes entropy into the generator, and marks it as initialized.
--- @param seed string The seed data.
local function init(seed)
    expect(1, seed, "string")
    mixHwSeed()
    state = blake3.digestKeyed(state, seed)
    initialized = true
end

--- Returns whether the generator has been initialized or not.
--- @return boolean
local function isInit()
    return initialized
end

--- Initializes the generator using VM instruction timing noise.
---
--- This function counts how many instructions the VM can execute within a single
--- millisecond, and mixes the lower bits of these values into the generator state.
--- The current implementation collects data for 512 ms and takes the lower 8 bits from
--- each count.
---
--- Compared to fetching entropy from a trusted web source, this approach is riskier but
--- more convenient. The factors that influence instruction timing suggest that this
--- seed is unpredictable for other players, but this assumption might turn out to be
--- untrue.
local function initWithTiming()
    mixHwSeed()
    assert(os.epoch("utc") ~= 0)

    local f = assert(load("local e=os.epoch return{" .. ("e'utc',"):rep(256) .. "}"))

    do -- Warmup.
        local t = f()
        while t[256] - t[1] > 1 do t = f() end
    end

    -- Fill up the buffer.
    local buf = {}
    for i = 1, 512 do
        local t = f()
        while t[256] == t[1] do t = f() end
        for j = 1, 256 do
            if t[j] ~= t[1] then
                buf[i] = j - 1
                break
            end
        end
    end

    -- Perform a histogram check to catch faulty os.epoch implementations.
    local hist = {}
    for i = 0, 255 do hist[i] = 0 end
    for i = 1, #buf do hist[buf[i]] = hist[buf[i]] + 1 end
    for i = 0, 255 do assert(hist[i] < 20) end

    init(string.char(table.unpack(buf)))
end

--- Initializes the generator with the best available source.
---
--- If no other sources are found, this function will resort to `initWithTiming`
--- as entropy source. See its documentation for security caveats.
local function initAuto()
    mixHwSeed()
    if not hwMixed then return initWithTiming() end
end

--- Mixes extra entropy into the generator state.
--- @param data string The additional entropy to mix.
local function mix(data)
    expect(1, data, "string")
    mixHwSeed()
    state = blake3.digestKeyed(state, data)
end

--- Generates random bytes.
--- @param len number The desired output length.
--- @return string bytes
local function random(len)
    len = math.max(0, expect(1, len, "number"))
    lassert(initialized, "attempt to use an uninitialized random generator", 2)
    local ok, out = hw.random(len)
    if ok then return out end

    mixHwSeed()
    local msg = ("\0"):rep(len + 32)
    local nonce = ("\0"):rep(12)
    local out = chacha20.crypt(state, nonce, msg, 8, 0)
    state = out:sub(1, 32)
    return out:sub(33)
end

return {
    init = init,
    isInit = isInit,
    initWithTiming = initWithTiming,
    initAuto = initAuto,
    mix = mix,
    random = random,
}
