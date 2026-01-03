
-- Bedwars ESP Loader
-- API: http://bedwarsapi.onrender.com/

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

-- Get script key from getgenv
if not getgenv then
    LocalPlayer:Kick("âŒ Executor not supported!")
    return
end

if not getgenv().scriptkey then
    LocalPlayer:Kick("âŒ Missing script key!\n\nUsage: scriptkey = \"YOUR_KEY\"; loadstring(game:HttpGet(...))()\n")
    return
end

local SCRIPT_KEY = getgenv().scriptkey
local API_URL = "http://bedwarsapi.onrender.com"
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()

-- Verify key with API
local function verifyKey()
    local success, result = pcall(function()
        local response = request({
            Url = API_URL .. "/verify-key",
            Method = "POST",
            Headers = {["Content-Type"] = "application/json"},
            Body = HttpService:JSONEncode({
                script_key = SCRIPT_KEY,
                hwid = HWID
            })
        })
        return HttpService:JSONDecode(response.Body)
    end)
    
    if not success or not result then
        LocalPlayer:Kick("âŒ Failed to connect to API!\n\n" .. tostring(result))
        return false
    end
    
    if result.blacklisted then
        LocalPlayer:Kick("ðŸš« HWID BLACKLISTED\n\nReason: " .. (result.reason or "Banned"))
        return false
    end
    
    if not result.valid then
        LocalPlayer:Kick("âŒ Invalid script key!\n\nGet a valid key from the Discord server.")
        return false
    end
    
    return true, result
end

-- Register HWID
local function registerHWID()
    pcall(function()
        request({
            Url = API_URL .. "/register-hwid",
            Method = "POST",
            Headers = {["Content-Type"] = "application/json"},
            Body = HttpService:JSONEncode({
                hwid = HWID,
                script_key = SCRIPT_KEY
            })
        })
    end)
end

-- Verify and load
print("ðŸ” Verifying script key...")
local verified, data = verifyKey()

if not verified then
    return
end

print("âœ… Key verified! Loading " .. data.script_name .. " v" .. data.version)

-- Register HWID in background
registerHWID()

-- Load the actual ESP script
loadstring(game:HttpGet(API_URL .. "/v3/files/scripts/esp-main.lua"))()
