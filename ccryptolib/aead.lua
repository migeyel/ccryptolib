--- The ChaCha20Poly1305AEAD authenticated encryption with associated data (AEAD) construction.
--
-- @module aead
--

local expect   = require "cc.expect".expect
local packing  = require "ccryptolib.internal.packing"
local chacha20 = require "ccryptolib.chacha20"
local poly1305 = require "ccryptolib.poly1305"

local p8x1, fmt8x1 = packing.compilePack("<I8")
local u4x4, fmt4x4 = packing.compileUnpack("<I4I4I4I4")
local bxor = bit32.bxor
local bor = bit32.bor

--- Encrypts a message.
--
-- @tparam string key A 32-byte random key.
-- @tparam string nonce A 12-byte per-message unique nonce.
-- @tparam string message The message to be encrypted.
-- @tparam string aad Arbitrary associated data to authenticate on decryption.
-- @tparam[opt=20] number rounds The number of ChaCha20 rounds to use.
-- @treturn string The ciphertext.
-- @treturn string The 16-byte authentication tag.
--
local function encrypt(key, nonce, message, aad, rounds)
    expect(1, key, "string")
    if #key ~= 32 then error("key length must be 32", 2) end
    expect(2, nonce, "string")
    if #nonce ~= 12 then error("nonce length must be 12", 2) end
    expect(3, message, "string")
    expect(4, aad, "string")
    rounds = expect(5, rounds, "number", "nil") or 20
    if rounds % 2 ~= 0 then error("round number must be even", 2) end
    if rounds < 8 then error("round number must be no smaller than 8", 2) end
    if rounds > 20 then error("round number must be no larger than 20", 2) end

    -- Generate auth key and encrypt.
    local msgLong = ("\0"):rep(64) .. message
    local ctxLong = chacha20.crypt(key, nonce, msgLong, rounds, 0)
    local authKey = ctxLong:sub(1, 32)
    local ciphertext = ctxLong:sub(65)

    -- Authenticate.
    local pad1 = ("\0"):rep(-#aad % 16)
    local pad2 = ("\0"):rep(-#ciphertext % 16)
    local aadLen = p8x1("<I8", #aad)
    local ctxLen = p8x1("<I8", #ciphertext)
    local combined = aad .. pad1 .. ciphertext .. pad2 .. aadLen .. ctxLen
    local tag = poly1305.mac(authKey, combined)

    return ciphertext, tag
end

--- Decrypts a message.
--
-- @tparam string key The key used on encryption.
-- @tparam string nonce The nonce used on encryption.
-- @tparam string ciphertext The ciphertext to be decrypted.
-- @tparam string aad The arbitrary associated data used on encryption.
-- @tparam string tag The authentication tag returned on encryption.
-- @tparam[opt=20] number rounds The number of rounds used on encryption.
-- @treturn[1] string The decrypted plaintext.
-- @treturn[2] nil If authentication has failed.
--
local function decrypt(key, nonce, tag, ciphertext, aad, rounds)
    expect(1, key, "string")
    if #key ~= 32 then error("key length must be 32", 2) end
    expect(2, nonce, "string")
    if #nonce ~= 12 then error("nonce length must be 12", 2) end
    expect(3, tag, "string")
    if #tag ~= 16 then error("tag length must be 16", 2) end
    expect(4, ciphertext, "string")
    expect(5, aad, "string")
    rounds = expect(6, rounds, "number", "nil") or 20
    if rounds % 2 ~= 0 then error("round number must be even", 2) end
    if rounds < 8 then error("round number must be no smaller than 8", 2) end
    if rounds > 20 then error("round number must be no larger than 20", 2) end

    -- Generate auth key.
    local authKey = chacha20.crypt(key, nonce, ("\0"):rep(32), rounds, 0)

    -- Check tag.
    local pad1 = ("\0"):rep(-#aad % 16)
    local pad2 = ("\0"):rep(-#ciphertext % 16)
    local aadLen = p8x1(fmt8x1, #aad)
    local ctxLen = p8x1(fmt8x1, #ciphertext)
    local combined = aad .. pad1 .. ciphertext .. pad2 .. aadLen .. ctxLen
    local t1, t2, t3, t4 = u4x4(fmt4x4, tag, 1)
    local u1, u2, u3, u4 = u4x4(fmt4x4, poly1305.mac(authKey, combined), 1)
    local eq = bxor(t1, u1) + bxor(t2, u2) + bxor(t3, u3) + bxor(t4, u4)
    if eq ~= 0 then return nil end

    -- Decrypt
    return chacha20.crypt(key, nonce, ciphertext, rounds)
end

return {
    encrypt = encrypt,
    decrypt = decrypt,
}
