local blake3   = require "ccryptolib.blake3"
local chacha20 = require "ccryptolib.chacha20"

-- Initialize from local context.
local ctx = {
    os.epoch("utc"),
    math.random(0, 2 ^ 24 - 1),
    math.random(0, 2 ^ 24 - 1),
    tostring({}),
    tostring({}),
}

local state = blake3.digest(table.concat(ctx, "|"), 32)

local function seed(data)
    state = blake3.digestKeyed(state, data, 32)
end

local function stir(n)
    -- Collect samples from jitter.
    local epoch = os.epoch
    local acc = {}
    local byte = 0
    for i = 1, n do
        local t0 = epoch("utc")
        repeat byte = byte + 1 until epoch("utc") ~= t0
        acc[i] = byte % 256
    end

    -- Extract into the new state.
    seed(string.char(table.unpack(acc)))
end

local function random(len)
    local msg = ("\0"):rep(len + 32)
    local nonce = ("\0"):rep(12)
    local out = chacha20.crypt(state, nonce, msg, 8, 0)
    state = out:sub(1, 32)
    return out:sub(33)
end

local function save()
    local file = fs.open("/.random", "wb")
    file.write(random(32))
    file.close()
end

-- Load.
if fs.exists("./random") then
    local file = fs.open("./random", "rb")
    seed(file.read(32) or "")
end

-- Add extra entropy.
stir(512)

-- Save.
math.randomseed(("I4"):unpack(random(4)))
save()

return {
    seed = seed,
    stir = stir,
    random = random,
    save = save,
}
