local expect   = require "cc.expect".expect
local blake3   = require "ccryptolib.blake3"
local chacha20 = require "ccryptolib.chacha20"
local packing  = require "ccryptolib.internal.packing"

local u1x4, fmt1x4 = packing.compileUnpack("<I4")

-- Initialize from local context.
local ctx = {
    "ccryptolib 2022-03-05T08:50:36Z random.lua initialization context",
    os.epoch("utc"),
    math.random(0, 2 ^ 24 - 1),
    math.random(0, 2 ^ 24 - 1),
    tostring({}),
    tostring({}),
}

local state = blake3.digest(table.concat(ctx, "|"))
local accumulator = {}
local accumulatorLen = 0

--- Adds data to the accumulator without context.
--
-- @tparam string data The input bytes.
--
local function reseed(data)
    local acc = accumulator
    local len = accumulatorLen

    -- Append to the accumulator.
    acc[#acc + 1] = data
    len = len + #data

    if len < 64 then
        accumulatorLen = len
        return
    end

    -- Concatenate.
    local cat = table.concat(acc)

    -- Align by 64-byte block.
    local rlen = len % 64
    local blen = len - rlen

    -- Digest.
    state = blake3.digestKeyed(state, cat:sub(1, blen))
    accumulator = {cat:sub(blen + 1)}
    accumulatorLen = rlen
end

do -- Load entropy from disk.
    local file = fs.open("/.random", "rb")
    if file then
        reseed(file.read(32) or "")
        file.close()
    end
end

local mod = {}

--- Adds entropy into the generator state.
--
-- @tparam string data The entropy data.
--
function mod.reseed(data)
    expect(1, data, "string")
    reseed(data)
end

--- Adds entropy from sampling system noise.
--
-- @tparam number n The number of iterations to spend extracting entropy.
--
function mod.stir(n)
    expect(1, n, "number")
    error("TODO") -- TODO
end

--- Generates random bytes.
--
-- @tparam number len The desired output length.
--
function mod.random(len)
    local msg = ("\0"):rep(len + 32)
    local nonce = ("\0"):rep(12)
    local out = chacha20.crypt(state, nonce, msg, 8, 0)
    state = out:sub(1, 32)
    return out:sub(33)
end

local random = mod.random

--- Saves the state to the filesystem.
--
-- This potentially adds security when starting the generator from boot. The
-- saved path is fixed and located at `/.random`.
--
function mod.save()
    local file = fs.open("/.random", "wb")
    file.write(random(32))
    file.close()
end

-- Add extra entropy.
mod.stir(error("TODO")) -- TODO

-- Save.
mod.save()

-- Regenerate the math.random seed.
math.randomseed(u1x4(fmt1x4, random(4), 1))

return mod
