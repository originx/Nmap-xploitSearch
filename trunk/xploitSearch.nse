description= [[
Get data from scanned ports and services with OS fingerprint (if exists)
and query exploitsearch.net to get possible number of exploits on specific service.
Use -oX filename.xml or similar for structured file output.

DISCLAIMER: number of shown exploits doesn't reflect possible number of security holes that exists on your server. exploitsearch.net crawls possible security databases and depending on the quality of the query returns different results.

TO DO:
-Improve OS fingerprint query if possible, results are sometimes unpredictable if there is not enough information
-Set http headers for more polite querys.
-Clean up code <- prehaps there are some finished libraries for eg. url escape chars.

Mentored under:
--FOI OSS--
-Faculty of Organisation and Informatics  - Open Systems and Security -
http://security.foi.hr/wiki/index.php/Glavna_stranica
Tonimir Ki�asondi
------------------------------------------------------------------------
]]
---
-- @usage
-- nmap -sC -O sitename.com -script xploitSearch.nse --script exploit-search.nse [--script-args detailed=<boolean> forcedOS=<String> exploitsOnly=<boolean> ] <target>
--
-- @args detailed Show detailed listing of found exploits (optional), recommended to be outputed to external file with -oX file.xml or simmilar technique because of possible verbosity.
-- @args forcedOS Manualy set detected operating system
-- @args exploitsOnly Force only showing pure exploits.
-- @output
-- PORT     STATE    SERVICE
-- 21/tcp   open     ftp
-- | xploitSearch:
-- |   numberOfExploits: 1
-- |_  onQuery:  Linux 2.4.36 tcp/21 ftp
-- 22/tcp   open     ssh
-- | xploitSearch:
-- |   numberOfExploits: 0
-- |_  onQuery:  Linux 2.4.36 tcp/22 ssh
-- 25/tcp   filtered smtp
-- 53/tcp   open     domain
-- | xploitSearch:
-- |   numberOfExploits: 0
-- |_  onQuery:  Linux 2.4.36 tcp/53 domain
-- 80/tcp   open     http
-- | xploitSearch:
-- |   numberOfExploits: 83
-- |_  onQuery:  Linux 2.4.36 tcp/80 http

author = "Mario Or�oli�"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

local stdnse = require("stdnse")
local http = require("http")
local json= require("json")

portrule = function(host, port)
	--ako je port nr razlicit od null ili servis ima naziv onda izvrsi action
	if port.number ~= nil or port.service~="" then
		return true
	end
end

action = function(host, port)
	--get script arguments
	--if user wants detailed output of every exploit
	local detailedFlag = stdnse.get_script_args("detailed") or "false"
	--manualy set detected OS
	local forcedOS = stdnse.get_script_args("forcedOS") or ""
	--force only showing exploits
	local exploitsOnly = stdnse.get_script_args("exploitsOnly") or "false"
	--args that will be sent to server
	local query=""
	--used for labeling of port and fingerprints
	local hostfound=false
	--check for params existence and append them to args
	--host information
	--if user forced specific OS omiting detection results
	if forcedOS ~= "" or forcedOS ~= nil then
		query = query .. " ".. forcedOS .. " "
		hostfound=true
	--otherwise try to detect automaticaly
	else
		if host.os ~=nil then
			--check and append osfamily
			if host.os[1].classes[1].osfamily ~=nil then
				query = query .. " ".. host.os[1].classes[1].osfamily 
			end
			--check and append os osgen
			if host.os[1].classes[1].osgen ~=nil then
				query = query .. " ".. host.os[1].classes[1].osgen .." "
			end
			--remove possible junk chars from query
			query = query:gsub("%.X", "")
			query = query:gsub("%.x", "")
			query = stripchars(query,"()")
			--set hostfound flag to true
			hostfound=true
		else
		hostfound=false
		end
	end
	--port/services informations
		--if port.number exists append it to query
		if port.number ~= nil then
			query = query ..port.protocol .."/".. port.number
				--if there is service name append it to query
				if port.version.name ~=nil and port.version.name ~="" or port.version.name ~= "unknown" then
				query = query .. " ".. port.version.name
				end
				--if there is service version append it to query
				if port.version.extrainfo ~=nil then
					query = query .. " ".. stripchars(port.version.extrainfo,";\\/-))((")
				end
				if port.version.version ~=nil then
					query = query .. " ".. stripchars(port.version.version,";\\/-))((")
				end
				if port.version.product ~=nil then
					query = query .. " ".. stripchars(port.version.product,";\\/-))((")
				end
				if port.version.ostype ~=nil then
					query = query .. " ".. stripchars(port.version.ostype,";\\/-))((")
				end
		end
	--if user forced to search only for exploits append it to query
	return checkForExploits(query,hostfound,detailedFlag,exploitsOnly)
end

function checkForExploits(query,hostFound,detailedFlag,exploitsOnly)
	--url for sending data
	local url= "exploitsearch.net"
	--clean query
	local label= query
	--check for exploits only flag and set it
	if exploitsOnly == "true" or exploitsOnly == true then
		query= query.. "&e=1"
	else
		query= query.. "&e=0"
	end
	--send query
	local response = http.get(url, 80, "/json.php?q=".. url_encode(query))
	--get and parse response with json module
	local status,data=json.parse(response.body)
	if  status then 
		if not hostFound then
			print ("OS version not detected, testing only on port/services....")
		end
		--if detailed is set, return full results
		if detailedFlag == true or detailedFlag=="true" then
		return data
		end
		--return summary of results
		local output = stdnse.output_table()
		output.numberOfExploits = #data
		output.onQuery = label
		return output
	end
	if not status then
		return "Bad response from exploitssearch.net"
	end
end

--strips inputed chars (chr) from string (str)
function stripchars( str, chr )
    local s = ""
    for g in str:gmatch( "[^"..chr.."]" ) do
 	s = s .. g
    end
    return s
end

--encode query string to url
function url_encode(str)
  if (str) then
    str = string.gsub (str, "\n", "\r\n")
    str = string.gsub (str, "([^%w ])",
        function (c) return string.format ("%%%02X", string.byte(c)) end)
    str = string.gsub (str, " ", "+")
  end
  return str	
end
