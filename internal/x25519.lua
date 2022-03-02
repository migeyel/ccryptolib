local fp = require "ccryptolib.internal.fp"

local G = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

local function double(x1, z1)
    local a = fp.add(x1, z1)
    local aa = fp.square(a)
    local b = fp.sub(x1, z1)
    local bb = fp.square(b)
    local c = fp.sub(aa, bb)
    local x3 = fp.mul(aa, bb)
    local z3 = fp.mul(c, fp.add(bb, fp.kmul(c, 121666)))
    return x3, z3
end

local function step(dx, x1, z1, x2, z2)
    local a = fp.add(x1, z1)
    local aa = fp.square(a)
    local b = fp.sub(x1, z1)
    local bb = fp.square(b)
    local e = fp.sub(aa, bb)
    local c = fp.add(x2, z2)
    local d = fp.sub(x2, z2)
    local da = fp.mul(d, a)
    local cb = fp.mul(c, b)
    local x4 = fp.square(fp.add(da, cb))
    local z4 = fp.mul(dx, fp.square(fp.sub(da, cb)))
    local x3 = fp.mul(aa, bb)
    local z3 = fp.mul(e, fp.add(bb, fp.kmul(e, 121666)))
    return x3, z3, x4, z4
end

return {
    G = G,
    double = double,
    step = step,
}
