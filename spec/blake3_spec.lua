--- Test vector specification for BLAKE3.
--
-- Derived from the official BLAKE3 test vectors.
--

local util = require "spec.util"
local blake3 = require "ccryptolib.blake3"

local hasVecs, vecs = pcall(require, "spec.bigvec.blake3")

local function mkInput(len)
    local out = {}
    for i = 1, len do out[i] = (i - 1) % 251 end
    return string.char(unpack(out))
end

describe("blake3.digest", function()
    it("validates arguments", function()
        -- Types
        expect.error(blake3.digest, nil)
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(blake3.digest, "", {})
            :eq("bad argument #2 (expected number, got table)")

        -- Length
        expect.error(blake3.digest, "", 0.5)
            :eq("desired output length must be an integer")
        expect.error(blake3.digest, "", 0)
            :eq("desired output length must be positive")
        expect.error(blake3.digest, "", 1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.digest, "", -1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.digest, "", 0 / 0)
            :eq("desired output length must be an integer")
    end)

    if not hasVecs then
        pending("passes the BLAKE3 official test vectors")
    else
        it("passes the BLAKE3 official test vectors", function()
            local cases = vecs.cases
            for i = 1, #cases do
                local input = mkInput(cases[i].inputLen)
                local hash = util.hexcat { cases[i].hash }
                expect(blake3.digest(input, #hash)):eq(hash)
                expect(blake3.digest(input)):eq(hash:sub(1, 32))
            end
        end)
    end
end)

describe("blake3.digestKeyed", function()
    it("validates arguments", function()
        local key = ("a"):rep(32)

        -- Types
        expect.error(blake3.digestKeyed, nil, "")
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(blake3.digestKeyed, key, nil)
            :eq("bad argument #2 (expected string, got nil)")
        expect.error(blake3.digestKeyed, key, "", {})
            :eq("bad argument #3 (expected number, got table)")

        -- String lengths
        expect.error(blake3.digestKeyed, key .. "a", "")
            :eq("key length must be 32")

        -- Length
        expect.error(blake3.digestKeyed, key, "", 0.5)
            :eq("desired output length must be an integer")
        expect.error(blake3.digestKeyed, key, "", 0)
            :eq("desired output length must be positive")
        expect.error(blake3.digestKeyed, key, "", 1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.digestKeyed, key, "", -1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.digestKeyed, key, "", 0 / 0)
            :eq("desired output length must be an integer")
    end)

    if not hasVecs then
        pending("passes the BLAKE3 official test vectors")
    else
        it("passes the BLAKE3 official test vectors", function()
            local key = vecs.key
            local cases = vecs.cases
            for i = 1, #cases do
                local input = mkInput(cases[i].inputLen)
                local keyedHash = util.hexcat { cases[i].keyedHash }
                expect(blake3.digestKeyed(key, input, #keyedHash)):eq(keyedHash)
                expect(blake3.digestKeyed(key, input)):eq(keyedHash:sub(1, 32))
            end
        end)
    end
end)

describe("blake3.deriveKey", function()
    it("validates arguments", function()
        -- Types
        expect.error(blake3.deriveKey, nil)
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(blake3.deriveKey(""), nil)
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(blake3.deriveKey(""), "", {})
            :eq("bad argument #2 (expected number, got table)")

        -- Length
        expect.error(blake3.deriveKey(""), "", 0.5)
            :eq("desired output length must be an integer")
        expect.error(blake3.deriveKey(""), "", 0)
            :eq("desired output length must be positive")
        expect.error(blake3.deriveKey(""), "", 1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.deriveKey(""), "", -1 / 0)
            :eq("desired output length must be an integer")
        expect.error(blake3.deriveKey(""), "", 0 / 0)
            :eq("desired output length must be an integer")
    end)

    if not hasVecs then
        pending("passes the BLAKE3 official test vectors")
    else
        it("passes the BLAKE3 official test vectors", function()
            local contextString = vecs.contextString
            local cases = vecs.cases
            for i = 1, #cases do
                local input = mkInput(cases[i].inputLen)
                local deriveKey = util.hexcat { cases[i].deriveKey }
                expect(blake3.deriveKey(contextString)(input, #deriveKey))
                    :eq(deriveKey)
                expect(blake3.deriveKey(contextString)(input))
                    :eq(deriveKey:sub(1, 32))
            end
        end)
    end
end)
