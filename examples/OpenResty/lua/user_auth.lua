-- ==============================
--     User Authentication
--      via X-Vouch-User
-- ==============================
-- Function to turn a table with only values into a k=>v table
function Set (list)
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end
-- Function to find a key in a table
function tableHasKey(table,key)
    return table[key] ~= nil
end
-- Validate a user in nginx, instead of vouch
local authorized_users = Set {
    "my@account.com",
    "friend@gmail.com"
}
-- Verify the variable exists
if ngx.var.auth_resp_x_vouch_user then
    -- Check if the found user is in the authorized_users table
    if not tableHasKey(authorized_users, ngx.var.auth_resp_x_vouch_user) then
        -- If not, throw a forbidden
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
else
    -- Throw forbidden if variable doesn't exist
    ngx.exit(ngx.HTTP_FORBIDDEN)
end
