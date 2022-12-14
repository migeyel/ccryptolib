--- Test vector specification for SHA512.
--
-- Derived from the NIST SHA512 Cryptographic Algorithm Validation Program.
--

local util = require "spec.util"
local sha512 = require "ccryptolib.internal.sha512"

local hasShort, shortMsg = pcall(require, "spec.bigvec.sha512short")
local hasLong, longMsg = pcall(require, "spec.bigvec.sha512long")

describe("sha256.digest", function()
    it("validates arguments", function()
        expect.error(sha512.digest, nil)
            :eq("bad argument #1 (expected string, got nil)")
    end)

    if not hasShort then
        pending("passes the NIST SHAVS byte-oriented short messages test")
    else
        it("passes the NIST SHAVS byte-oriented short messages test", function()
            for i = 1, #shortMsg do
                local msg = util.hexcat { shortMsg[i].msg }
                local md = util.hexcat { shortMsg[i].md }
                expect(sha512.digest(msg)):eq(md)
                sleep()
            end
        end)
    end

    if not hasLong then
        pending("passes the NIST SHAVS byte-oriented long messages test")
    else
        it("passes the NIST SHAVS byte-oriented long messages test", function()
            for i = 1, #longMsg do
                local msg = util.hexcat { longMsg[i].msg }
                local md = util.hexcat { longMsg[i].md }
                expect(sha512.digest(msg)):eq(md)
                sleep()
            end
        end)
    end

    it("passes the NIST SHAVS monte carlo test (5k iterations)", function()
        local seed = util.hexcat {
            "5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd",
        }

        for _ = 1, 5 do
            local md0, md1, md2 = seed, seed, seed
            for _ = 1, 1000 do
                md0, md1, md2 = md1, md2, sha512.digest(md0 .. md1 .. md2)
            end
            seed = md2
            sleep()
        end

        local out = util.hexcat {
            "b68f0cd2d63566b3934a50666dec6d62ca1db98e49d7733084c1f86d91a8a08c756fa7ece815e20930dd7cb66351bad8c087c2f94e8757cb98e7f4b86b21a8a8",
        }

        expect(seed):eq(out)
    end)
end)
