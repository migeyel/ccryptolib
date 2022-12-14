local function hexcat(t)
    return table.concat(t):gsub("[^%x]*(%x%x)[^%x]*", function(h)
        return string.char(tonumber(h, 16))
    end)
end

return {
    hexcat = hexcat,
}
