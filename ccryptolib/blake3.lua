--- The BLAKE3 cryptographic hash function.
--
-- @module blake3
--

local expect  = require "cc.expect".expect
local lassert = require "ccryptolib.internal.util".lassert
local packing = require "ccryptolib.internal.packing"

local unpack = unpack or table.unpack
local bxor = bit32.bxor
local rol = bit32.lrotate
local p16x4, fmt16x4 = packing.compilePack("<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)
local u8x4, fmt8x4 = packing.compileUnpack("<I4I4I4I4I4I4I4I4")

local CHUNK_START         = 0x01
local CHUNK_END           = 0x02
local PARENT              = 0x04
local ROOT                = 0x08
local KEYED_HASH          = 0x10
local DERIVE_KEY_CONTEXT  = 0x20
local DERIVE_KEY_MATERIAL = 0x40

local IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local function compress(h, msg, t, v14, v15, full)
    local h00, h01, h02, h03, h04, h05, h06, h07 = unpack(h)
    local v00, v01, v02, v03 = h00, h01, h02, h03
    local v04, v05, v06, v07 = h04, h05, h06, h07
    local v08, v09, v10, v11 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local v12 = t % 2 ^ 32
    local v13 = (t - v12) * 2 ^ -32

    local m00, m01, m02, m03, m04, m05, m06, m07,
          m08, m09, m10, m11, m12, m13, m14, m15 = unpack(msg)

    local tmp
    for i = 1, 7 do
        v00 = v00 + v04 + m00 v12 = rol(bxor(v12, v00), 16)
        v08 = v08 + v12       v04 = rol(bxor(v04, v08), 20)
        v00 = v00 + v04 + m01 v12 = rol(bxor(v12, v00), 24)
        v08 = v08 + v12       v04 = rol(bxor(v04, v08), 25)

        v01 = v01 + v05 + m02 v13 = rol(bxor(v13, v01), 16)
        v09 = v09 + v13       v05 = rol(bxor(v05, v09), 20)
        v01 = v01 + v05 + m03 v13 = rol(bxor(v13, v01), 24)
        v09 = v09 + v13       v05 = rol(bxor(v05, v09), 25)

        v02 = v02 + v06 + m04 v14 = rol(bxor(v14, v02), 16)
        v10 = v10 + v14       v06 = rol(bxor(v06, v10), 20)
        v02 = v02 + v06 + m05 v14 = rol(bxor(v14, v02), 24)
        v10 = v10 + v14       v06 = rol(bxor(v06, v10), 25)

        v03 = v03 + v07 + m06 v15 = rol(bxor(v15, v03), 16)
        v11 = v11 + v15       v07 = rol(bxor(v07, v11), 20)
        v03 = v03 + v07 + m07 v15 = rol(bxor(v15, v03), 24)
        v11 = v11 + v15       v07 = rol(bxor(v07, v11), 25)

        v00 = v00 + v05 + m08 v15 = rol(bxor(v15, v00), 16)
        v10 = v10 + v15       v05 = rol(bxor(v05, v10), 20)
        v00 = v00 + v05 + m09 v15 = rol(bxor(v15, v00), 24)
        v10 = v10 + v15       v05 = rol(bxor(v05, v10), 25)

        v01 = v01 + v06 + m10 v12 = rol(bxor(v12, v01), 16)
        v11 = v11 + v12       v06 = rol(bxor(v06, v11), 20)
        v01 = v01 + v06 + m11 v12 = rol(bxor(v12, v01), 24)
        v11 = v11 + v12       v06 = rol(bxor(v06, v11), 25)

        v02 = v02 + v07 + m12 v13 = rol(bxor(v13, v02), 16)
        v08 = v08 + v13       v07 = rol(bxor(v07, v08), 20)
        v02 = v02 + v07 + m13 v13 = rol(bxor(v13, v02), 24)
        v08 = v08 + v13       v07 = rol(bxor(v07, v08), 25)

        v03 = v03 + v04 + m14 v14 = rol(bxor(v14, v03), 16)
        v09 = v09 + v14       v04 = rol(bxor(v04, v09), 20)
        v03 = v03 + v04 + m15 v14 = rol(bxor(v14, v03), 24)
        v09 = v09 + v14       v04 = rol(bxor(v04, v09), 25)

        if i ~= 7 then
            tmp = m02
            m02 = m03
            m03 = m10
            m10 = m12
            m12 = m09
            m09 = m11
            m11 = m05
            m05 = m00
            m00 = tmp

            tmp = m06
            m06 = m04
            m04 = m07
            m07 = m13
            m13 = m14
            m14 = m15
            m15 = m08
            m08 = m01
            m01 = tmp
        end
    end

    if full then
        return {
            bxor(v00, v08), bxor(v01, v09), bxor(v02, v10), bxor(v03, v11),
            bxor(v04, v12), bxor(v05, v13), bxor(v06, v14), bxor(v07, v15),
            bxor(v08, h00), bxor(v09, h01), bxor(v10, h02), bxor(v11, h03),
            bxor(v12, h04), bxor(v13, h05), bxor(v14, h06), bxor(v15, h07),
        }
    else
        return {
            bxor(v00, v08), bxor(v01, v09), bxor(v02, v10), bxor(v03, v11),
            bxor(v04, v12), bxor(v05, v13), bxor(v06, v14), bxor(v07, v15),
        }
    end
end

local function merge(cvl, cvr)
    for i = 1, 8 do cvl[i + 8] = cvr[i] end
    return cvl
end

local function expand(state, len, offset)
    expect(1, state, "table")
    expect(1, len, "number")
    lassert(len % 1 == 0, "desired output length must be an integer", 2)
    lassert(len >= 1, "desired output length must be positive", 2)
    offset = expect(2, offset, "nil", "number") or 0
    lassert(offset % 1 == 0, "offset must be an integer", 2)
    lassert(offset >= 0, "offset must be nonnegative", 2)
    lassert(offset + len <= 2 ^ 32, "offset is too large", 2)

    -- Expand output.
    local out = {}
    for i = 0, len / 64 do
        local n = offset + i
        local md = compress(state.cv, state.m, n, state.n, state.f, true)
        out[i + 1] = p16x4(fmt16x4, unpack(md))
    end

    return table.concat(out):sub(1, len)
end

local function update(state, message)
    expect(1, state, "table")
    expect(1, message, "string")

    -- Append to buffer.
    state.m = state.m .. message

    -- Split off complete blocks.
    local blockslen = #state.m - (#state.m - 1) % 64 - 1
    local blocks = state.m:sub(1, blockslen)
    state.m = state.m:sub(1 + blockslen)

    -- Digest complete blocks.
    for i = 1, #blocks, 64 do
        -- Compress the block.
        local block = {u16x4(fmt16x4, blocks, i)}
        local stateFlags = state.f + state.s + state.e
        state.cv = compress(state.cv, block, state.t, 64, stateFlags)
        state.s = 0
        state.n = state.n + 1

        if state.n == 15 then
            -- Last block in chunk.
            state.e = CHUNK_END
        elseif state.n == 16 then
            -- Chunk complete, merge.
            local mergeCv = state.cv
            local mergeAmt = state.t + 1
            while mergeAmt % 2 == 0 do
                local block = merge(table.remove(state.cvs), mergeCv)
                mergeCv = compress(state.iv, block, 0, 64, state.f + PARENT)
                mergeAmt = mergeAmt / 2
            end

            -- Push back.
            table.insert(state.cvs, mergeCv)

            -- Update state back to next chunk.
            state.cv = state.iv
            state.t = state.t + 1
            state.n = 0
            state.s = CHUNK_START
            state.e = 0
        end
    end

    return state
end

local function finalize(state)
    expect(1, state, "table")

    -- Pad the last message block.
    local lastLen = #state.m
    local padded = state.m .. ("\0"):rep(64)
    local last = {u16x4(fmt16x4, padded, 1)}

    -- Prepare output expansion state.
    if state.t > 0 then
        -- Root is a parent, digest last block now and merge parents.
        local stateFlags = state.f + state.s + CHUNK_END
        local mergeCv = compress(state.cv, last, state.t, lastLen, stateFlags)
        for i = #state.cvs, 2, -1 do
            local block = merge({unpack(state.cvs[i])}, mergeCv)
            mergeCv = compress(state.iv, block, 0, 64, state.f + PARENT)
        end

        -- Set output state.
        return {
            expand = expand,
            cv = {unpack(state.iv)},
            m = merge({unpack(state.cvs[1])}, mergeCv),
            n = 64,
            f = state.f + ROOT + PARENT,
        }
    else
        -- Root is in the first chunk, set output state.
        return {
            expand = expand,
            cv = {unpack(state.cv)},
            m = last,
            n = lastLen,
            f = state.f + state.s + CHUNK_END + ROOT,
        }
    end
end

local function copy(state)
    -- Copy CV stack.
    local cvs = {}
    for i = 1, #state.cvs do cvs[i] = {unpack(state.cvs[i])} end

    return {
        update = update,
        finalize = finalize,
        copy = copy,
        iv = {unpack(state.iv)},
        cv = {unpack(state.cv)},
        cvs = cvs,
        m = state.m,
        t = state.t,
        n = state.n,
        s = state.s,
        e = state.e,
        f = state.f,
    }
end

local function new(iv, f)
    return {
        update = update,
        finalize = finalize,
        copy = copy,
        iv = iv,
        cv = iv,
        cvs = {},
        m = "",
        t = 0,
        n = 0,
        s = CHUNK_START,
        e = 0,
        f = f,
    }
end

local mod = {}

function mod.new()
    return new({unpack(IV)}, 0)
end

function mod.newKeyed(key)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    return new({u8x4(fmt8x4, key, 1)}, KEYED_HASH)
end

function mod.newDk(context)
    expect(1, context, "string")
    local iv = new(IV, DERIVE_KEY_CONTEXT):update(context):finalize():expand(32)
    return new({u8x4(fmt8x4, iv, 1)}, DERIVE_KEY_MATERIAL)
end

--- Hashes data using BLAKE3.
--
-- @tparam string message The input message.
-- @tparam[opt=32] number len The desired hash length, in bytes.
-- @treturn string The hash.
--
function mod.digest(message, len)
    expect(1, message, "string")
    len = expect(2, len, "number", "nil") or 32
    lassert(len % 1 == 0, "desired output length must be an integer", 2)
    lassert(len >= 1, "desired output length must be positive", 2)
    return new(IV, 0):update(message):finalize():expand(len)
end

--- Performs a keyed hash.
--
-- @tparam string key A 32-byte random key.
-- @tparam string message The input message.
-- @tparam[opt=32] number len The desired hash length, in bytes.
-- @treturn string The keyed hash.
--
function mod.digestKeyed(key, message, len)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, message, "string")
    len = expect(3, len, "number", "nil") or 32
    lassert(len % 1 == 0, "desired output length must be an integer", 2)
    lassert(len >= 1, "desired output length must be positive", 2)
    local h = new({u8x4(fmt8x4, key, 1)}, KEYED_HASH)
    return h:update(message):finalize():expand(len)
end

--- Makes a context-based key derivation function (KDF).
--
-- @tparam string context The context for the KDF.
-- @treturn function(material:string [, len:number]):string The KDF.
--
function mod.deriveKey(context)
    expect(1, context, "string")
    local iv = new(IV, DERIVE_KEY_CONTEXT):update(context):finalize():expand(32)

    return function(material, len)
        expect(1, material, "string")
        len = expect(2, len, "number", "nil") or 32
        lassert(len % 1 == 0, "desired output length must be an integer", 2)
        lassert(len >= 1, "desired output length must be positive", 2)
        local h = new({u8x4(fmt8x4, iv, 1)}, DERIVE_KEY_MATERIAL)
        return h:update(material):finalize():expand(len)
    end
end

return mod
