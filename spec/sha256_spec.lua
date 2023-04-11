--- Test vector specification for SHA256.
--
-- Derived from the NIST SHA256 Cryptographic Algorithm Validation Program.
--

local util = require "spec.util"
local sha256 = require "ccryptolib.sha256"

local shortMsg = require "spec.vec.sha256.short"
local longMsg = require "spec.vec.sha256.long"

describe("sha256.digest", function()
    it("validates arguments", function()
        expect.error(sha256.digest, nil)
            :eq("bad argument #1 (expected string, got nil)")
    end)

    it("passes the NIST SHAVS byte-oriented short messages test", function()
        for i = 1, #shortMsg do
            local msg = util.hexcat { shortMsg[i].msg }
            local md = util.hexcat { shortMsg[i].md }
            expect(sha256.digest(msg)):eq(md)
            sleep()
        end
    end)

    it("passes the NIST SHAVS byte-oriented long messages test", function()
        for i = 1, #longMsg do
            local msg = util.hexcat { longMsg[i].msg }
            local md = util.hexcat { longMsg[i].md }
            expect(sha256.digest(msg)):eq(md)
            sleep()
        end
    end)

    it("passes the NIST SHAVS monte carlo test (5k iterations)", function()
        local seed = util.hexcat {
            "6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691",
        }

        for _ = 1, 5 do
            local md0, md1, md2 = seed, seed, seed
            for _ = 1, 1000 do
                md0, md1, md2 = md1, md2, sha256.digest(md0 .. md1 .. md2)
            end
            seed = md2
            sleep()
        end

        local out = util.hexcat {
            "f9eba2a4cf6263826beaf6150057849eb975a9513c0b76ecad0f1c19ebbad89b",
        }

        expect(seed):eq(out)
    end)
end)
