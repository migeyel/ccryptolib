local PROFILE_TIME_MS = 2000

local function profile(fmt, fun, coeff)
    local tStart = os.epoch("utc")
    local sum = 0
    local count = 0
    repeat
        local t0 = os.epoch("utc")
        fun()
        local t1 = os.epoch("utc")
        sum = sum + t1 - t0
        count = count + 1
        if count ~= 1 then
            local x, y = term.getCursorPos()
            term.setCursorPos(1, y - 1)
            term.clearLine()
        end
        print(fmt:format(coeff * count / sum))
    until t1 - tStart > PROFILE_TIME_MS
    sleep()
end

local random = require "ccryptolib.random"
random.init("mock random init")

local m = random.random(100000)
local block = random.random(32)
local nonce = random.random(12)

local blake3 = require "ccryptolib.blake3"

profile(
    "BLAKE3 input rate: %g kB/s",
    function() blake3.digest(m) end,
    #m
)

profile(
    "BLAKE3 output rate: %g kB/s",
    function() blake3.digest(block, 100000) end,
    100000
)

profile(
    "BLAKE3 short input rate: %g msg/s",
    function() for _ = 1, 1000 do blake3.digest(block) end end,
    1e6
)

local sha256 = require "ccryptolib.sha256"

profile(
    "SHA256 input rate: %g kB/s",
    function() sha256.digest(m) end,
    #m
)

profile(
    "SHA256 short input rate: %g msg/s",
    function() for _ = 1, 1000 do sha256.digest(block) end end,
    1e6
)

profile(
    "PBKDF2-HMAC-SHA256 rate: %g iter/s",
    function() sha256.pbkdf2(block, block, 1000) end,
    1e6
)

local chacha20 = require "ccryptolib.chacha20"

profile(
    "ChaCha20 enciphering rate: %g kB/s",
    function() chacha20.crypt(block, nonce, m, 20) end,
    #m
)

profile(
    "ChaCha8 enciphering rate: %g kB/s",
    function() chacha20.crypt(block, nonce, m, 8) end,
    #m
)

local poly1305 = require "ccryptolib.poly1305"

profile(
    "Poly1305 input rate: %g kB/s",
    function() poly1305.mac(block, m) end,
    #m
)

local aead = require "ccryptolib.aead"

profile(
    "ChaCha20Poly1305AEAD input rage: %g kB/s",
    function() aead.encrypt(block, nonce, m, "", 20) end,
    #m
)

profile(
    "ChaCha8Poly1305AEAD input rage: %g kB/s",
    function() aead.encrypt(block, nonce, m, "", 8) end,
    #m
)

local x25519 = require "ccryptolib.x25519"
local xpk = x25519.publicKey(block)

profile(
    "X25519 public key: %g op/s",
    function() x25519.publicKey(block) end,
    1000
)

profile(
    "X25519 exchange: %g op/s",
    function() x25519.exchange(block, xpk) end,
    1000
)

local ed25519 = require "ccryptolib.ed25519"
local epk = ed25519.publicKey(block)
local sigb = ed25519.sign(block, epk, block)
local sigm = ed25519.sign(block, epk, m)

profile(
    "Ed25519 public key: %g op/s",
    function() ed25519.publicKey(block) end,
    1000
)

profile(
    "Ed25519 sign short msg: %g op/s",
    function() ed25519.sign(block, epk, block) end,
    1000
)

profile(
    "Ed25519 sign long msg: %g kB/s",
    function() ed25519.sign(block, epk, m) end,
    #m
)

profile(
    "Ed25519 verify short msg: %g op/s",
    function() ed25519.verify(epk, block, sigb) end,
    1000
)

profile(
    "Ed25519 verify long msg: %g kB/s",
    function() ed25519.verify(epk, m, sigm) end,
    #m
)
