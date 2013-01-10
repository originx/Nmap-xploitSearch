description= [[
Uhvati podatke od skeniranih portova i servisa te ih vraæe
u obliku os.name | port.number | port.service | port.version
]]

author = "Mario Orsolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local stdnse = require("stdnse")
local nmap = require("nmap")
local http = require("http")
local table = require "table"

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

	local url= "exploitsearch.net"
	local arguments="/json.php?q="
	if port.number ~= nil then
		arguments = arguments .. " ".. port.number
	end
	--provjeri parametre koji se prosljedjuju upitu i ako postoje dodaj ih
	if port.version ~=nil then
		arguments = arguments .. " ".. port.version.name
	end
		if port.number ~= nil then
		arguments = arguments .. " ".. port.number
	end
	if host.os[1].name ~=nil then
		arguments = arguments .. " ".. host.os[1].name
	end
	--makni zagrade i ostali junk koji može zbuniti server po potrebi
	arguments = stripchars(arguments,"()")
	--posalji upit
	local response = http.get(url, 80, "/json.php?q=80%20and%20tcp%20%20and%20http%20and%20Linux%202.4.36&e=1")
	--poguce je dodati na kraj " &e=1" da se eksplicitno traže exploiti
	-- ovo bi se cak moglo dodati kao argument skripti
	--vrati json odgovor
	return response.body
end


function stripchars( str, chr )
    local s = ""
    for g in str:gmatch( "[^"..chr.."]" ) do
 	s = s .. g
    end
    return s
end