-- Bedwars ESP Loader - Updated Edition
-- Each user has their own personal key

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

-- Check if scriptkey variable exists
if not scriptkey then
    LocalPlayer:Kick("❌ Missing script key!\n\nUsage:\nscriptkey = \"YOUR_KEY\";\nloadstring(game:HttpGet(...))()")
    return
end

local PERSONAL_KEY = scriptkey
local API_URL = "https://bedwarsapi.onrender.com"  -- HTTPS not HTTP!
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()

print("🔐 Verifying your personal key...")
print("📍 HWID: " .. HWID:sub(1, 16) .. "...")

-- Verify key with API
local function verifyKey()
    local success, result = pcall(function()
        -- Use game:HttpPost for Roblox
        local response = game:HttpPost(
            API_URL .. "/verify-key",
            HttpService:JSONEncode({
                script_key = PERSONAL_KEY,
                hwid = HWID
            }),
            Enum.HttpContentType.ApplicationJson
        )
        return HttpService:JSONDecode(response)
    end)
    
    if not success then
        local errorMsg = tostring(result)
        warn("❌ API Error: " .. errorMsg)
        
        -- Better error messages
        if errorMsg:find("403") or errorMsg:find("Forbidden") then
            LocalPlayer:Kick("❌ INVALID KEY!\n\nYour key was rejected by the API.\n\nGet your key from Discord using /getscript")
        elseif errorMsg:find("Http requests are not enabled") then
            LocalPlayer:Kick("❌ HTTP REQUESTS NOT ENABLED!\n\nEnable HttpService in game settings.")
        else
            LocalPlayer:Kick("❌ Failed to connect to API!\n\n" .. errorMsg)
        end
        return false
    end
    
    if not result then
        LocalPlayer:Kick("❌ No response from API!")
        return false
    end
    
    if result.blacklisted then
        LocalPlayer:Kick("🚫 HWID BLACKLISTED\n\nReason: " .. (result.reason or "Banned"))
        return false
    end
    
    if not result.valid then
        LocalPlayer:Kick("❌ " .. (result.error or "Invalid key") .. "\n\nGet your key from Discord using /getscript")
        return false
    end
    
    return true, result
end

-- Verify and load
local verified, data = verifyKey()

if not verified then
    return
end

print("✅ Authenticated as: " .. data.username)
print("✅ Loading " .. data.script_name .. " v" .. data.version)

-- Load the actual ESP script
local success, err = pcall(function()
    loadstring(game:HttpGet(API_URL .. "/v3/files/scripts/esp-main.lua"))()
end)

if not success then
    warn("❌ ESP Load Error: " .. tostring(err))
    LocalPlayer:Kick("❌ Failed to load ESP!\n\n" .. tostring(err))
end
