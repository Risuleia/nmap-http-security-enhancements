
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enhancement 2: reports HTTP status, page title,
and the presence of selected HTTP security headers.
For authorised testing.
]]

author = "Hreeth Gupta"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if not response then
        return "No HTTP response received"
    end

    local output = {}
    local headers = response.header or {}

    table.insert(output,
        "HTTP Status: " ..
        (response.status and tostring(response.status) or "Unknown")
    )

    local body = response.body or ""
    local title = body:match(
        "<[Tt][Ii][Tt][Ll][Ee][^>]*>(.-)</[Tt][Ii][Tt][Ll][Ee]>"
    )

    if title then
        title = title:gsub("%s+", " "):match("^%s*(.-)%s*$")
        table.insert(output, "Page Title: " .. title)
    else
        table.insert(output, "Page Title: Not found")
    end

    local checks = {
        {"Content-Security-Policy", "content-security-policy"},
        {"Strict-Transport-Security", "strict-transport-security"},
        {"X-Content-Type-Options", "x-content-type-options"},
        {"X-Frame-Options", "x-frame-options"}
    }

    for _, item in ipairs(checks) do
        local value = headers[item[2]]

        if value then
            table.insert(output,
                item[1] .. ": Present (" .. tostring(value) .. ")")
        else
            table.insert(output, item[1] .. ": Not present")
        end
    end

    return stdnse.format_output(true, output)
end
