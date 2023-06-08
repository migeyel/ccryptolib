--- Test vector specification for ChaCha20Poly1305AEAD.
--
-- Derived from RFC 7539.
--

local util = require "spec.util"
local aead = require "ccryptolib.aead"

describe("aead.encrypt", function()
    it("validates arguments", function()
        local key = ("a"):rep(32)
        local nonce = ("a"):rep(12)
        local msg = ("a"):rep(179)
        local aad = ("a"):rep(79)
        local rounds = 20

        -- Types
        expect.error(aead.encrypt, nil, nonce, msg, aad, rounds)
            :eq("bad argument #1 (string expected, got nil)")
        expect.error(aead.encrypt, key, nil, msg, aad, rounds)
            :eq("bad argument #2 (string expected, got nil)")
        expect.error(aead.encrypt, key, nonce, nil, aad, rounds)
            :eq("bad argument #3 (string expected, got nil)")
        expect.error(aead.encrypt, key, nonce, msg, nil, rounds)
            :eq("bad argument #4 (string expected, got nil)")
        expect.error(aead.encrypt, key, nonce, msg, aad, {})
            :eq("bad argument #5 (number expected, got table)")

        -- String lengths
        expect.error(aead.encrypt, key .. "a", nonce, msg, aad, rounds)
            :eq("key length must be 32")
        expect.error(aead.encrypt, key, nonce .. "a", msg, aad, rounds)
            :eq("nonce length must be 12")

        -- Rounds
        expect.error(aead.encrypt, key, nonce, msg, aad, 19.5)
            :eq("round number must be even")
        expect.error(aead.encrypt, key, nonce, msg, aad, 19)
            :eq("round number must be even")
        expect.error(aead.encrypt, key, nonce, msg, aad, 6)
            :eq("round number must be no smaller than 8")
        expect.error(aead.encrypt, key, nonce, msg, aad, 22)
            :eq("round number must be no larger than 20")
        expect.error(aead.encrypt, key, nonce, msg, aad, 1 / 0)
            :eq("round number must be even")
        expect.error(aead.encrypt, key, nonce, msg, aad, -1 / 0)
            :eq("round number must be even")
        expect.error(aead.encrypt, key, nonce, msg, aad, 0 / 0)
            :eq("round number must be even")
    end)

    it("encrypts the section 2.8.2 test vector", function()
        local plaintext = table.concat {
            "Ladies and Gentlemen of the class of '99: If I could offer you o",
            "nly one tip for the future, sunscreen would be it.",
        }

        local aad = util.hexcat {
            "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7",
        }

        local key = util.hexcat {
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f",
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        }

        local nonce = util.hexcat {
            "07 00 00 00 40 41 42 43 44 45 46 47",
        }

        local ciphertext = util.hexcat {
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2",
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6",
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b",
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36",
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58",
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc",
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b",
            "61 16                                          ",
        }

        local tag = util.hexcat {
            "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91",
        }

        local cCiphertext, cTag = aead.encrypt(key, nonce, plaintext, aad)

        expect(cCiphertext):equals(ciphertext)
        expect(cTag):equals(tag)
    end)

    it("encrypts the appendix A.5 test vector", function()
        local plaintext = table.concat {
            "Internet-Drafts are draft documents valid for a maximum of six m",
            "onths and may be updated, replaced, or obsoleted by other docume",
            "nts at any time. It is inappropriate to use Internet-Drafts as r",
            "eference material or to cite them other than as /\xe2\x80\x9cwor",
            "k in progress./\xe2\x80\x9d",
        }

        local aad = util.hexcat {
            "f3 33 88 86 00 00 00 00 00 00 4e 91",
        }

        local key = util.hexcat {
            "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
            "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
        }

        local nonce = util.hexcat {
            "00 00 00 00 01 02 03 04 05 06 07 08",
        }

        local ciphertext = util.hexcat {
            "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd",
            "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2",
            "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0",
            "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf",
            "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81",
            "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55",
            "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38",
            "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4",
            "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9",
            "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e",
            "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a",
            "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a",
            "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e",
            "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10",
            "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30",
            "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29",
            "a6 ad 5c b4 02 2b 02 70 9b                     ",
        }

        local tag = util.hexcat {
            "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38",
        }

        local cCiphertext, cTag = aead.encrypt(key, nonce, plaintext, aad)

        expect(cCiphertext):equals(ciphertext)
        expect(cTag):equals(tag)
    end)


end)

describe("aead.decrypt", function()
    it("validates arguments", function()
        local key = ("a"):rep(32)
        local nonce = ("a"):rep(12)
        local tag = ("a"):rep(16)
        local ctx = ("a"):rep(179)
        local aad = ("a"):rep(79)
        local rounds = 20

        -- Types
        expect.error(aead.decrypt, nil, nonce, tag, ctx, aad, rounds)
            :eq("bad argument #1 (string expected, got nil)")
        expect.error(aead.decrypt, key, nil, tag, ctx, aad, rounds)
            :eq("bad argument #2 (string expected, got nil)")
        expect.error(aead.decrypt, key, nonce, nil, ctx, aad, rounds)
            :eq("bad argument #3 (string expected, got nil)")
        expect.error(aead.decrypt, key, nonce, tag, nil, aad, rounds)
            :eq("bad argument #4 (string expected, got nil)")
        expect.error(aead.decrypt, key, nonce, tag, ctx, nil, rounds)
            :eq("bad argument #5 (string expected, got nil)")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, {})
            :eq("bad argument #6 (number expected, got table)")

        -- String lengths
        expect.error(aead.decrypt, key .. "a", nonce, tag, ctx, aad, rounds)
            :eq("key length must be 32")
        expect.error(aead.decrypt, key, nonce .. "a", tag, ctx, aad, rounds)
            :eq("nonce length must be 12")
        expect.error(aead.decrypt, key, nonce, tag .. "a", ctx, aad, rounds)
            :eq("tag length must be 16")

        -- Rounds
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 19.5)
            :eq("round number must be even")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 19)
            :eq("round number must be even")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 6)
            :eq("round number must be no smaller than 8")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 22)
            :eq("round number must be no larger than 20")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 1 / 0)
            :eq("round number must be even")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, -1 / 0)
            :eq("round number must be even")
        expect.error(aead.decrypt, key, nonce, tag, ctx, aad, 0 / 0)
            :eq("round number must be even")
    end)

    it("decrypts the section 2.8.2 test vector", function()
        local plaintext = table.concat {
            "Ladies and Gentlemen of the class of '99: If I could offer you o",
            "nly one tip for the future, sunscreen would be it.",
        }

        local aad = util.hexcat {
            "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7",
        }

        local key = util.hexcat {
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f",
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        }

        local nonce = util.hexcat {
            "07 00 00 00 40 41 42 43 44 45 46 47",
        }

        local ciphertext = util.hexcat {
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2",
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6",
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b",
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36",
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58",
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc",
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b",
            "61 16                                          ",
        }

        local tag = util.hexcat {
            "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91",
        }

        expect(aead.decrypt(key, nonce, tag, ciphertext, aad))
            :eq(plaintext)
    end)

    it("returns nil on invalid ciphertext", function()
        local aad = util.hexcat {
            "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7",
        }

        local key = util.hexcat {
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f",
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        }

        local nonce = util.hexcat {
            "07 00 00 00 40 41 42 43 44 45 46 47",
        }

        local ciphertext = util.hexcat {
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c3", -- Bit flip
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6",
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b",
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36",
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58",
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc",
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b",
            "61 16                                          ",
        }

        local tag = util.hexcat {
            "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91",
        }

        expect(aead.decrypt(key, nonce, tag, ciphertext, aad))
            :eq(nil)
    end)

    it("returns nil on invalid AAD", function()
        local aad = util.hexcat {
            "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c6", -- Bit flip
        }

        local key = util.hexcat {
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f",
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        }

        local nonce = util.hexcat {
            "07 00 00 00 40 41 42 43 44 45 46 47",
        }

        local ciphertext = util.hexcat {
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2",
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6",
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b",
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36",
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58",
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc",
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b",
            "61 16                                          ",
        }

        local tag = util.hexcat {
            "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91",
        }

        expect(aead.decrypt(key, nonce, tag, ciphertext, aad))
            :eq(nil)
    end)

    it("returns nil on invalid tag", function()
        local aad = util.hexcat {
            "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7",
        }

        local key = util.hexcat {
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f",
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        }

        local nonce = util.hexcat {
            "07 00 00 00 40 41 42 43 44 45 46 47",
        }

        local ciphertext = util.hexcat {
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2",
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6",
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b",
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36",
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58",
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc",
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b",
            "61 16                                          ",
        }

        local tag = util.hexcat {
            "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:90", -- Bit flip
        }

        expect(aead.decrypt(key, nonce, tag, ciphertext, aad))
            :eq(nil)
    end)

    it("decrypts the appendix A.5 test vector", function()
        local plaintext = table.concat {
            "Internet-Drafts are draft documents valid for a maximum of six m",
            "onths and may be updated, replaced, or obsoleted by other docume",
            "nts at any time. It is inappropriate to use Internet-Drafts as r",
            "eference material or to cite them other than as /\xe2\x80\x9cwor",
            "k in progress./\xe2\x80\x9d",
        }

        local aad = util.hexcat {
            "f3 33 88 86 00 00 00 00 00 00 4e 91",
        }

        local key = util.hexcat {
            "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
            "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
        }

        local nonce = util.hexcat {
            "00 00 00 00 01 02 03 04 05 06 07 08",
        }

        local ciphertext = util.hexcat {
            "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd",
            "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2",
            "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0",
            "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf",
            "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81",
            "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55",
            "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38",
            "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4",
            "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9",
            "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e",
            "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a",
            "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a",
            "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e",
            "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10",
            "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30",
            "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29",
            "a6 ad 5c b4 02 2b 02 70 9b                     ",
        }

        local tag = util.hexcat {
            "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38",
        }

        expect(aead.decrypt(key, nonce, tag, ciphertext, aad))
            :eq(plaintext)
    end)
end)
