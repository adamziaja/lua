local stdnse = require "stdnse"
--local table = require "table"

description = [[
Script checks connectivity (whether last hop is target).
]]

---
-- @usage
-- sudo nmap -Pn --script=connectivity --traceroute target
-- 
-- @output
-- Host script results:
-- |_connectivity: YES
---

author = "Adam Ziaja <adam@adamziaja.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  if not host.traceroute then
    stdnse.debug("Skipping %s script because traceroute results are missing.", SCRIPT_NAME)
    return false
  end
  return true
end

action = function(host)
  --local hops = {}
  --hops['name'] = "HOPS"
  --local connectivity = {}
  --connectivity['name'] = "CONNECTIVITY"
  local hoplast = ""
  --local hopno = 0
  for _, hop in ipairs(host.traceroute) do -- targets-traceroute.nse
    --hopno = hopno + 1
    --table.insert(hops, hopno .. ". " .. hop.ip)
    if hop.ip == host.ip then
      hoplast = "YES"
    else
      hoplast = "NO"
    end
  end
  
  --table.insert(connectivity, hoplast)

  --local response = {}
  --table.insert(response, hops)
  --table.insert(response, connectivity)
  --return stdnse.format_output(true, response) -- https://nmap.org/nsedoc/lib/stdnse.html#format_output
  return string.format("%s\n", hoplast)
end
