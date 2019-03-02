local http = require "http"
local string = require "string"
local stdnse = require "stdnse"
local table = require "table"

local out = stdnse.output_table()
http.useragent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'

portrule = function(host,port)
	if port.state == "open" and port.protocol == "tcp" then
		local r = http.get(host,port,'/wp-login.php')
		if r.status == 200 and string.find(r.body, 'wp.admin') then
			out.cms = "WordPress"
			return true
		else
			return false
		end
	end

	return false
end

action = function(host,port)
	local rbody = http.get(host,port,'/')
	local rfeed = http.get(host,port,'/?feed=rss2')

	if rbody.status == 200 then
		local _,_,version = string.find(rbody.body, 'meta.+generator.+content..WordPress ([0-9\\.]+)')
		if version then
			out.cmsversion = version
		end

		local _,_,version = string.find(rbody.body, 'css.ver.([0-9\\.]+)')
		if version then
			out.cmsversion = version
		end
	end

	if out.cmsversion then
		table.insert(port.version.cpe, 'cpe:/a:wordpress:wordpress:'..out.cmsversion)
		nmap.set_port_version(host, port)
	end

	return out
end
