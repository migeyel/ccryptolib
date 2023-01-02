--- Test vector specification for Ed25519.
--
-- Derived from RFC 8032.
--

local util = require "spec.util"
local ed25519 = require "ccryptolib.ed25519"

describe("ed25519.verify", function()
    it("passes the section 7.1 test 1", function()
        local sk = util.hexcat {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        }

        local pk = util.hexcat {
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        }

        local m = ""

        local sig = util.hexcat {
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        }

        expect(ed25519.publicKey(sk)):eq(pk)
        expect(ed25519.verify(pk, m, sig)):eq(true)
    end)

    it("passes the section 7.1 test 2", function()
        local sk = util.hexcat {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        }

        local pk = util.hexcat {
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        }

        local m = util.hexcat {
            "72",
        }

        local sig = util.hexcat {
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        }

        expect(ed25519.publicKey(sk)):eq(pk)
        expect(ed25519.verify(pk, m, sig)):eq(true)
    end)

    it("passes the section 7.1 test 3", function()
        local sk = util.hexcat {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        }

        local pk = util.hexcat {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        }

        local m = util.hexcat {
            "af82",
        }

        local sig = util.hexcat {
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        }

        expect(ed25519.publicKey(sk)):eq(pk)
        expect(ed25519.verify(pk, m, sig)):eq(true)
    end)

    it("returns false on an invalid signature", function()
        local pk = util.hexcat {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        }

        local m = util.hexcat {
            "af83", -- Bit flip
        }

        local sig = util.hexcat {
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        }

        expect(ed25519.verify(pk, m, sig)):eq(false)
    end)
end)
