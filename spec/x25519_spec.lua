--- Test vector specification for X25519.
--
-- Derived from RFC 7748.
--

local util = require "spec.util"
local x25519 = require "ccryptolib.x25519"

describe("x25519.exchange", function()
    it("passes the section 5.2 test vector #1", function()
        local x = util.hexcat {
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        }

        local p = util.hexcat {
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        }

        local q = util.hexcat {
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        }

        expect(x25519.exchange(x, p)):eq(q)
    end)

    it("passes the section 5.2 test vector #2", function()
        local x = util.hexcat {
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        }

        local p = util.hexcat {
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        }

        local q = util.hexcat {
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        }

        expect(x25519.exchange(x, p)):eq(q)
    end)

    it("passes the section 5.2 test vector #3 (1k iterations)", function()
        local k = util.hexcat {
            "0900000000000000000000000000000000000000000000000000000000000000",
        }

        local u = k
        local u2 = util.hexcat {
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        }

        expect(x25519.exchange(k, u)):eq(u2)

        for _ = 1, 1000 do
            k, u = x25519.exchange(k, u), k
            sleep()
        end

        local k1000 = util.hexcat {
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        }

        expect(k):eq(k1000)
    end)
end)
