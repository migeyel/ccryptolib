local expect = require "cc.expect".expect

local usePeripheralsValue = true

--- Sets whether to use peripheral calls for computation. Defaults to true.
---
--- If this is true, ccryptolib will search for compatible peripherals every few
--- seconds. If a compatible peripheral is found, ccryptolib will offload some
--- of its computation to it, improving performance.
---
--- No peripheral searches are performed until you first call a ccryptolib
--- function. Setting this value to false beforehand guarantees no searches will
--- ever be made.
---
--- @param value boolean? The new setting. If nil then no changes are made.
--- @return boolean value The current setting. Includes any changes made.
local function usePeripherals(value)
    expect(1, value, "boolean", "nil")
    if value ~= nil then usePeripheralsValue = value end
    return usePeripheralsValue
end

return {
    usePeripherals = usePeripherals,
}
