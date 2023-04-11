--- Test vector specification for X25519.
--
-- Derived from RFC 7748.
--

local util = require "spec.util"
local x25519 = require "ccryptolib.x25519"

require "ccryptolib.random".init("mock initialization")

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

    it("passes the appendix A.1 test vectors of CPace", function()
        local sk = util.hexcat {
            "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
        }

        local ins = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }

        local outs = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
            "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
            "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
            "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
            "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
        }

        for i = 1, #ins do
            local input = util.hexcat { ins[i] }
            local output = util.hexcat { outs[i] }
            expect(x25519.exchange(sk, input)):eq(output)
        end
    end)
end)
