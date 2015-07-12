local stdnse = require "stdnse"
local table = require "table"

description = [[
CPE
]]

---
-- @usage
-- sudo nmap -Pn -sV --script=cpe target
-- 
-- @output
-- cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
---

author = "Adam Ziaja <adam@adamziaja.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "version"}

portrule = function(host, port)
  if port.version.cpe[1] ~= nil then
    return true
  else
  	return false
  end
end

action = function(host, port)
  return string.format("%s\n", port.version.cpe[1])
end
