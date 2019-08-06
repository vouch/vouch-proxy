-- ==============================
--     Group Authentication
--    via X-Vouch-IdP-Groups
-- ==============================
-- Validate that a user is in a group
local authorized_groups = Set {
    "Domain Users",
    "Website Users"
}
-- Verify the variable exists
if ngx.var.auth_resp_x_vouch_idp_claims_groups then
    -- Check if the found user is in the allowed_users table
    local cjson = require("cjson")
    local groups = cjson.decode(ngx.var.auth_resp_x_vouch_idp_claims_groups)
    local found = false
    -- Parse the groups and check if they match any of our authorized groups
    for i, group in ipairs(groups) do
        if tableHasKey(authorized_groups, group) then
            -- If we found an authorized group, say so and break the loop
            found = true
            break
        end
    end
    -- If we didn't find out group in our list, then return forbidden
    if not found then
        -- If not, throw a forbidden
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
else
    -- Throw forbidden if variable doesn't exist
    ngx.exit(ngx.HTTP_FORBIDDEN)
end