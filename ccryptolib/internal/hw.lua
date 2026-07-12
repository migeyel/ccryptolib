local config = require "ccryptolib.config"

local PERIPHERAL_CHECK_INTERVAL = 10

local peripheralName = nil
local peripheralType = nil
local peripheralSeed = nil
local lastCheck = -PERIPHERAL_CHECK_INTERVAL

local function isClassicPeripherals(name)
    local methods = peripheral.getMethods(name)
    if type(methods) ~= "table" then return false end
    local kMethods = {}
    for _, method in ipairs(methods) do
        kMethods[method] = true
    end
    if not kMethods.computeSharedSecret then return false end
    if not kMethods.deriveEcdhPublicKey then return false end
    if not kMethods.derivePublicKey then return false end
    if not kMethods.randomBytes then return false end
    if not kMethods.sha256 then return false end
    if not kMethods.sha512 then return false end
    if not kMethods.sign then return false end
    if not kMethods.verify then return false end
    return true
end

local function findPeripheral()
    if peripheralName ~= nil then return end
    if os.clock() - lastCheck < PERIPHERAL_CHECK_INTERVAL then return end
    lastCheck = os.clock()

    if not peripheral then
        config.usePeripherals(false)
        return
    end

    local found = peripheral.find("cryptographic_accelerator", isClassicPeripherals)
    if found then
        peripheralName = peripheral.getName(found)
        peripheralType = "cryptographic_accelerator"
        local ok, seed = pcall(peripheral.call, peripheralName, "randomBytes", 32)
        if ok then peripheralSeed = seed end
    end
end

local function takeSeed()
    if not config.usePeripherals() then return end
    findPeripheral()
    local out = peripheralSeed
    peripheralSeed = nil
    return out
end

local function checkedCall(method, ...)
    if not config.usePeripherals() then return false end
    findPeripheral()
    if not peripheralName then return false end
    if peripheral.hasType(peripheralName, peripheralType) then
        local ok, out = pcall(peripheral.call, peripheralName, method, ...)
        if not ok or out == nil then return false end
        return true, out
    else
        peripheralName = nil
        peripheralType = nil
        return false
    end
end

local function x25519Exchange(sk, pk)
    return checkedCall("computeSharedSecret", sk, pk)
end

local function x25519PublicKey(sk)
    return checkedCall("deriveEcdhPublicKey", sk)
end

local function ed25519PublicKey(sk)
    return checkedCall("derivePublicKey", sk)
end

local function random(length)
    return checkedCall("randomBytes", length)
end

local function sha256(input)
    return checkedCall("sha256", input, false)
end

local function sha512(input)
    return checkedCall("sha512", input, false)
end

local function ed25519Sign(m, sk)
    return checkedCall("sign", m, sk)
end

local function ed25519Verify(m, s, pk)
    return checkedCall("verify", m, s, pk)
end

return {
    takeSeed = takeSeed,
    x25519Exchange = x25519Exchange,
    x25519PublicKey = x25519PublicKey,
    ed25519PublicKey = ed25519PublicKey,
    random = random,
    sha256 = sha256,
    sha512 = sha512,
    ed25519Sign = ed25519Sign,
    ed25519Verify = ed25519Verify,
}
