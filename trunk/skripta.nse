description= [[
Uhvati podatke od skeniranih portova i servisa te ih vraæe
u obliku os.name | port.number | port.service | port.version
]]

author = "Mario Orsolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local stdnse = require("stdnse")
local nmap = require("nmap")

portrule = function(host, port)
	--ako je port nr razlicit od null ili servis ima naziv onda izvrsi action
	if port.number ~= nil or port.service~="" then
		return true
	end
end

action = function(host, port)
	local result = {}
	--local output = stdnse.output_table()
	--result=port.number .." | ".. port.service .. " | " .. host.os[1].name
	--return result 
	
	--strukturirani stdnse izlaz
	local output = stdnse.output_table()
	output.hostname = host.os[1].name
	output.portNumber = port.number
	output.portService=port.service
	output.portVersion=port.version
	return output
end