--- Test vector specification for ChaCha20.
--
-- Derived from RFC 7539.
--

local util = require "spec.util"
local chacha20 = require "ccryptolib.chacha20"

describe("chacha20.crypt", function()
    it("validates arguments", function()
        local key = ("a"):rep(32)
        local nonce = ("a"):rep(12)
        local msg = ("a"):rep(179)
        local rounds = 20
        local offset = 1

        -- Types
        expect.error(chacha20.crypt, nil, nonce, msg, rounds, offset)
            :eq("bad argument #1 (expected string, got nil)")
        expect.error(chacha20.crypt, key, nil, msg, rounds, offset)
            :eq("bad argument #2 (expected string, got nil)")
        expect.error(chacha20.crypt, key, nonce, nil, rounds, offset)
            :eq("bad argument #3 (expected string, got nil)")
        expect.error(chacha20.crypt, key, nonce, msg, {}, offset)
            :eq("bad argument #4 (expected number, got table)")
        expect.error(chacha20.crypt, key, nonce, msg, nil, {})
            :eq("bad argument #5 (expected number, got table)")

        -- String lengths
        expect.error(chacha20.crypt, key .. "a", nonce, msg, rounds, offset)
            :eq("key length must be 32")
        expect.error(chacha20.crypt, key, nonce .. "a", msg, rounds, offset)
            :eq("nonce length must be 12")

        -- Rounds
        expect.error(chacha20.crypt, key, nonce, msg, 19.5, offset)
            :eq("round number must be even")
        expect.error(chacha20.crypt, key, nonce, msg, 19, offset)
            :eq("round number must be even")
        expect.error(chacha20.crypt, key, nonce, msg, 6, offset)
            :eq("round number must be no smaller than 8")
        expect.error(chacha20.crypt, key, nonce, msg, 22, offset)
            :eq("round number must be no larger than 20")
        expect.error(chacha20.crypt, key, nonce, msg, 1 / 0, offset)
            :eq("round number must be even")
        expect.error(chacha20.crypt, key, nonce, msg, -1 / 0, offset)
            :eq("round number must be even")
        expect.error(chacha20.crypt, key, nonce, msg, 0 / 0, offset)
            :eq("round number must be even")

        -- Offset
        expect.error(chacha20.crypt, key, nonce, msg, rounds, 1.1)
            :eq("offset must be an integer")
        expect.error(chacha20.crypt, key, nonce, msg, rounds, -1)
            :eq("offset must be nonnegative")
        expect.error(chacha20.crypt, key, nonce, msg, rounds, 2 ^ 32)
            :eq("offset too large")
        expect.error(chacha20.crypt, key, nonce, msg, rounds, 1 / 0)
            :eq("offset must be an integer")
        expect.error(chacha20.crypt, key, nonce, msg, rounds, -1 / 0)
            :eq("offset must be an integer")
        expect.error(chacha20.crypt, key, nonce, msg, rounds, 0 / 0)
            :eq("offset must be an integer")
    end)

    it("encrypts the section 2.4.2 test vector", function()
        local key = util.hexcat {
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f",
            "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
        }

        local nonce = util.hexcat {
            "00:00:00:00:00:00:00:4a:00:00:00:00"
        }

        local plaintextSunscreen = table.concat {
            "Ladies and Gentlemen of the class of '99: If I could offer you o",
            "nly one tip for the future, sunscreen would be it.",
        }

        local ciphertextSunscreen = util.hexcat {
            "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81",
            "e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b",
            "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57",
            "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8",
            "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e",
            "52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36",
            "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42",
            "87 4d                                          ",
        }

        expect(chacha20.crypt(key, nonce, plaintextSunscreen))
            :eq(ciphertextSunscreen)
    end)

    it("encrypts the appendix A.2 test vector #1", function()
        local key = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local nonce = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local plaintext = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        }

        local ciphertext = util.hexcat {
            "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28",
            "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7",
            "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37",
            "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86",
        }

        expect(chacha20.crypt(key, nonce, plaintext, 20, 0))
            :eq(ciphertext)
    end)

    it("encrypts the appendix A.2 test vector #2", function()
        local key = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",
        }

        local nonce = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 02",
        }

        local plaintext = table.concat {
            "Any submission to the IETF intended by the Contributor for publi",
            "cation as all or part of an IETF Internet-Draft or RFC and any s",
            "tatement made within the context of an IETF activity is consider",
            'ed an "IETF Contribution". Such statements include oral statemen',
            "ts in IETF sessions, as well as written and electronic communica",
            "tions made at any time or place, which are addressed to",
        }

        local ciphertext = util.hexcat {
            "a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70",
            "41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec",
            "2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05",
            "0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d",
            "40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e",
            "20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50",
            "42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c",
            "68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a",
            "d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66",
            "42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d",
            "c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28",
            "e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b",
            "08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f",
            "a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c",
            "cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84",
            "a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b",
            "c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0",
            "8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f",
            "58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62",
            "be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6",
            "98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85",
            "14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab",
            "7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd",
            "c4 fd 80 6c 22 f2 21                           ",
        }

        expect(chacha20.crypt(key, nonce, plaintext, 20, 1))
            :eq(ciphertext)
    end)

    it("encrypts the appendix A.2 test vector #3", function()
        local key = util.hexcat {
            "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
            "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
        }

        local nonce = util.hexcat {
            "00 00 00 00 00 00 00 00 00 00 00 02",
        }

        local plaintext = table.concat {
            "'Twas brillig, and the slithy toves\nDid gyre and gimble in the w",
            "abe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.",
        }

        local ciphertext = util.hexcat {
            "62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df",
            "5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf",
            "16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71",
            "fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb",
            "f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6",
            "1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77",
            "04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1",
            "87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1   ",
        }

        expect(chacha20.crypt(key, nonce, plaintext, 20, 42))
            :eq(ciphertext)
    end)
end)
