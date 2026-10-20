local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Retrieves an HTTP page title and reports the HTTP status code.
Designed for authorised security testing.
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

    return stdnse.format_output(true, output)
end