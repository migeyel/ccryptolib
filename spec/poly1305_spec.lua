--- Test vector specification for Poly1305.
--
-- Derived from RFC 7539.
--

local util = require "spec.util"
local poly1305 = require "ccryptolib.poly1305"

describe("poly1305.mac", function()
    it("validates arguments", function()
        local key = ("a"):rep(32)
        local msg = ("a"):rep(179)

        -- Types
        expect.error(poly1305.mac, nil, msg)
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(poly1305.mac, key, nil)
            :eq("bad argument #2 (expected string, got nil)")

        -- Key length
        expect.error(poly1305.mac, key .. "a", msg)
            :eq("key length must be 32")
    end)

    it("derives the tag of the section 2.5.2 test vector", function()
        local key = util.hexcat {
            "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8",
            "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
        }

        local message = "Cryptographic Forum Research Group"

        local tag = util.hexcat {
            "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #1", function()
        local key = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local tag = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #2", function()
        local key = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
        }

        local message = table.concat {
            "Any submission to the IETF intended by the Contributor for publi",
            "cation as all or part of an IETF Internet-Draft or RFC and any s",
            "tatement made within the context of an IETF activity is consider",
            'ed an "IETF Contribution". Such statements include oral statemen',
            "ts in IETF sessions, as well as written and electronic communica",
            "tions made at any time or place, which are addressed to",
        }

        local tag = util.hexcat {
            "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #3", function()
        local key = util.hexcat {
            "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = table.concat {
            "Any submission to the IETF intended by the Contributor for publi",
            "cation as all or part of an IETF Internet-Draft or RFC and any s",
            "tatement made within the context of an IETF activity is consider",
            'ed an "IETF Contribution". Such statements include oral statemen',
            "ts in IETF sessions, as well as written and electronic communica",
            "tions made at any time or place, which are addressed to",
        }

        local tag = util.hexcat {
            "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #4", function()
        local key = util.hexcat {
            "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
            "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
        }

        local message = table.concat {
            "'Twas brillig, and the slithy toves\nDid gyre and gimble in the w",
            "abe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.",
        }

        local tag = util.hexcat {
            "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #5", function()
        local key = util.hexcat {
            "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        }

        local tag = util.hexcat {
            "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #6", function()
        local key = util.hexcat {
            "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        }

        local message = util.hexcat {
            "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local tag = util.hexcat {
            "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #7", function()
        local key = util.hexcat {
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
            "F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
            "11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local tag = util.hexcat {
            "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #8", function()
        local key = util.hexcat {
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
            "FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE",
            "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
        }

        local tag = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #9", function()
        local key = util.hexcat {
            "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        }

        local tag = util.hexcat {
            "FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #10", function()
        local key = util.hexcat {
            "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00",
            "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local tag = util.hexcat {
            "14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)

    it("derives the tag of the appendix A.2 test vector #10", function()
        local key = util.hexcat {
            "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local message = util.hexcat {
            "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00",
            "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local tag = util.hexcat {
            "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        expect(poly1305.mac(key, message)):eq(tag)
    end)
end)
