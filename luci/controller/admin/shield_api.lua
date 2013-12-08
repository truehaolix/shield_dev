module("luci.controller.admin.shield_api", package.seeall)

function index()
	entry({"admin", "shield"},template("admin_web/shield_index"))

	entry({"admin", "shield", "info"}, template("admin_web/info"), nil)
	entry({"admin", "shield", "devices_list"}, template("admin_web/device_list"), nil)

	entry({"admin", "shield" , "settings"}, template("admin_web/index"), nil)
	entry({"admin", "shield" , "settings","lan"}, template("admin_web/lan"), nil)
	entry({"admin", "shield" , "settings", "channel"}, template("admin_web/channel"), nil)
	entry({"admin", "shield" , "settings", "dhcp"}, template("admin_web/dhcp"), nil)
	entry({"admin", "shield" , "settings", "l2tp"}, template("admin_web/l2tp"), nil)
	entry({"admin", "shield" , "settings", "mac"}, template("admin_web/mac"), nil)
	entry({"admin", "shield" , "settings", "mac_filter"}, template("admin_web/mac_filter"), nil)
	entry({"admin", "shield" , "settings", "mtu"}, template("admin_web/mtu"), nil)
	entry({"admin", "shield" , "settings", "ppp_adv"}, template("admin_web/ppp_adv"), nil)
	entry({"admin", "shield" , "settings", "systime"}, template("admin_web/systime"), nil)
	entry({"admin", "shield" , "settings", "upnp"}, template("admin_web/upnp"), nil)
	entry({"admin", "shield" , "settings", "update_manger"}, template("admin_web/update_manger"), nil)
	entry({"admin", "shield" , "settings", "reset"}, template("admin_web/reset"), nil)
	entry({"admin", "shield" , "settings", "diagnose"}, template("admin_web/diagnose"), nil)

	entry({"admin", "shield" , "modify_password"}, template("admin_web/modify_password"), nil)
	entry({"admin", "shield" , "net_detect"}, template("admin_web/net_detect"), nil)
	entry({"admin", "shield" , "network"}, template("admin_web/network"), nil)
	entry({"admin", "shield" , "set_wifi"}, template("admin_web/set_wifi"), nil)
	entry({"admin", "shield" , "web_status"}, template("admin_web/web_status"), nil)

	entry({"admin", "shield" , "lansetup1"}, call("lansetup1"),nil)
	entry({"admin", "shield","get_lan_info"}, call("send_lan_info"))
	entry({"admin", "shield","lansetup_ip"}, call("lansetup_ip"))
	entry({"admin", "shield","set_systime"}, call("set_systime"))
	entry({"admin", "shield","wansetup"},call("wansetup"))
	entry({"admin", "shield","set_sys_password"},call("set_sys_password"))
	entry({"admin", "shield","modify_password"},template("admin_web/modify_password"))
	entry({"admin", "shield", "logout"}, call("action_logout"), _("Logout"), 90)
	entry({"admin", "shield", "reboot"}, call("action_reboot"), _("reboot"), 90)

	entry({"admin", "shield", "usbinfo"},call('usbopt'),nil)
	entry({"admin", "shield", "usbtimer"},call('usbtimer'),nil)
	entry({"admin", "shield", "usbadd"},call('usbadd'),nil)
	entry({"admin", "shield", "usbremove"},call('usbremove'),nil)
	entry({"admin", "shield", "usbaddmain"},call('usbaddmain'),nil)
	entry({"admin", "shield", "usbremovemain"},call('usbremovemain'),nil)

	entry({"admin", "shield", "fileview"}, call("file_view"),nil)
	entry({"admin", "shield", "fileview", "fileviewlist"}, call("fileviewlist"),nil)
	entry({"admin", "shield", "fileview", "downloadfile"}, call("downloadfile"),nil)
	entry({"admin", "shield", "fileview", "lanipaddrcheck"}, call("landownloadcheck"),nil)


end

function Split(szFullString, szSeparator)  
	local nFindStartIndex = 1  
	local nSplitIndex = 1  
	local nSplitArray = {}
	while true do  
	   local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)  
	   if not nFindLastIndex then  
	    nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))
	    break  
	   end  
	   nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)
	   nFindStartIndex = nFindLastIndex + string.len(szSeparator)
	   nSplitIndex = nSplitIndex + 1  
	end  
	return nSplitArray  
end

function action_logout()
	local dsp = require "luci.dispatcher"
	local sauth = require "luci.sauth"
	if dsp.context.authsession then
		sauth.kill(dsp.context.authsession)
		dsp.context.urltoken.stok = nil
	end

	luci.http.header("Set-Cookie", "sysauth=; path=" .. dsp.build_url())
	luci.http.redirect(luci.dispatcher.build_url())
end

function action_reboot()
	require "luci.http"
	local o = {}
	o['code'] = 0
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
	luci.sys.reboot()
end

function send_lan_info()
	local uci = require "luci.model.uci".cursor()
	local mac = uci.get('network','lan','macaddr')
	local ipaddr = uci.get('network','lan','ipaddr')
	local netmask = uci.get('network','lan','netmask')
	local o={}
	o['ipv4'] = ipaddr
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function lansetup_ip()
	require "luci.http"
	local uci = require "luci.model.uci".cursor()
	local ipaddr 	= luci.http.formvalue('ip')
	local o_ipaddr 	= uci.get('network','lan','ipaddr')

	if ipaddr ~= o_ipaddr then
		luci.sys.exec('uci set network.lan.ipaddr='..ipaddr)
		luci.sys.exec('uci commit')
		luci.sys.exec('/usr/local/localshell/updatehostip '..ipaddr)
		luci.sys.exec('reboot')
	end

	local o = {}
	o['result'] = o_ipaddr
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function set_systime()
	require "luci.http"
	require "luci.sys"
	local data_ = luci.http.formvalue("date")
	local pattern = "(%d+)-(%d+)-(%d+)"
	year_,month_,day_ = data_:match(pattern)
	local h_ = tonumber(luci.http.formvalue("h"))
	local m_ = tonumber(luci.http.formvalue("mi"))
	local s_ = tonumber(luci.http.formvalue("s"))
	if data_ ~= nil then
		local date = os.date("*t",  os.time{year=year_,month=month_,day=day_,hour=h_,min=m_,sec=s_})
		if date then
			luci.sys.call("date -s '%04d-%02d-%02d %02d:%02d:%02d'" %{
				date.year, date.month, date.day, date.hour, date.min, date.sec
			})
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({ timestring = os.date("%c"),code=0})
end

function wifiStatus()
	local uci = require "luci.model.uci".cursor()
	local ntm = require "luci.model.network"
	ntm.init(uci)

	local devices  = ntm:get_wifidevs()
	local devs
	local netlist = {}
	for _, dev in ipairs(devices) do local nets = dev:get_wifinets()
		local nets = dev:get_wifinets()
		for _, net in ipairs(nets) do
			netlist[#netlist+1] = net:id()
		end
	end

	local netmd = require "luci.model.network".init()
	local net = netmd:get_wifinet(netlist[1])
	local dev = net:get_device()

	local result = nil
	if dev and net then
		result = net:get("disabled")
	end

	local o = {}
	if result then
		o['test'] = "close"
	else
		o['test'] = "open"
	end

	luci.http.prepare_content('application/json')
	luci.http.write_json(o)
end

function wansetup()

	local h = require "luci.http"
	local uci = require "luci.model.uci".cursor()

	local type = h.formvalue("network_type")
	if type == "ip" then
		type = h.formvalue("ip_type")
	end	
	
	local o = {}

	local network_tb = uci:get_all("network","wan")

	for k,v in pairs (network_tb) do
		if k ~= '.name' and k ~= 'ifname' and k ~= '.anonymous' then
			luci.sys.exec('uci del network.wan.'..k)
		end
	end

	if type == "dhcp" then
		luci.sys.exec('uci set network.wan.proto=dhcp')
	elseif type == "pppoe" then
		local name 	 = 	h.formvalue("pppoe_name")
		local passwd = 	h.formvalue("pppoe_passwd")
		luci.sys.exec('uci set network.wan.proto=pppoe')
		luci.sys.exec('uci set network.wan.username='..name)
		luci.sys.exec('uci set network.wan.password='..passwd)
	elseif type == "static" then
		local ip = h.formvalue("static_ip")
		local netmask = h.formvalue("static_mask")
		local gateway = h.formvalue("static_gw")
		local dns = h.formvalue("static_dns")

		luci.sys.exec('uci set network.wan.proto=static')
		luci.sys.exec('uci set network.wan.ipaddr='..ip)
		luci.sys.exec('uci set network.wan.netmask='..netmask)
		luci.sys.exec('uci set network.wan.gateway='..gateway)
		luci.sys.exec('uci set network.wan.dns='..dns)
	end

	luci.sys.exec('uci commit')
	luci.sys.exec('/etc/init.d/network restart')

	o['code'] = '0'
	
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function set_sys_password()
	local h = require "luci.http"
	local v0 = h.formvalue("old_password")
	local v1 = h.formvalue("password")
	local v2 = h.formvalue("password2")
	local o = {}

	if not luci.sys.user.checkpasswd(luci.dispatcher.context.authuser, v0) then
		 o["code"]=1
		 o["msg"]="wrong password"
	elseif v1 and v2 and #v1 > 0 and #v2 > 0 then
		if v1 == v2 then
			if luci.sys.user.setpasswd(luci.dispatcher.context.authuser, v1) == 0 then
				o["code"]=0
				o["msg"]= "Password successfully changed!"
			else
				o["code"]=1
			end
		else
			o["code"] = 2
			o["msg"]= "Given password confirmation did not match, password not changed!"
		end
	end
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function usbremovemain()
	require 'luci.http'

	local device=luci.http.formvalue('dev')

	local res=luci.sys.exec('/usr/local/localshell/usb-mount remove '..device)
	local len=string.len(res)

	local o = {}
	o['result'] = len
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function usbaddmain()
	require 'luci.http'
	require 'luci.sys'

	local res1=luci.sys.exec('/usr/local/localshell/usbdevice')
	local len=0
	--如果有挂载分区 就删除上一个分区
	local tmp=Split(res1,"/////")
	if tmp[3] ~= 'NULL' then
		luci.sys.exec('/usr/local/localshell/usb-mount remove '..tmp[3])
	end

	local device=luci.http.formvalue('dev')

	local res=luci.sys.exec('/usr/local/localshell/usb-mount add '..device)
	len=string.len(res)

	local o = {}
	o['result'] = len
	luci.http.prepare_content("application/json")
    luci.http.write_json(o)
end

function usbadd()
	require 'luci.sys'
	require 'luci.http'

	luci.sys.exec('/usr/local/localshell/usb-mount add')

	local n = {}

	luci.http.prepare_content("application/json")
    luci.http.write_json(n)
end

function usbremove()
	require 'luci.sys'
	require 'luci.http'

	local n = {}

	luci.sys.exec('/usr/local/localshell/usb-mount remove')

	luci.http.prepare_content("application/json")
    luci.http.write_json(n)
end

function usbopt()
	require 'luci.template'
	require 'luci.sys'

	local content = luci.sys.exec('/usr/local/localshell/usbdevice')
	local o = Split(content,'/////')


	luci.template.render("admin_web/usbopt",{dev_name=o[1],status=string.len(content)},nil)
end

function usbtimer()
	require 'luci.template'
	require 'luci.sys'
	require 'luci.http'

	local content = luci.sys.exec('/usr/local/localshell/usbdevice')
	local n = {}

	if content ~= "" then
		local o = Split(content,'////')
		n['optname'] = o[1]
		n['status'] = string.sub(o[2],1,string.len(o[2])-1)
	else
		n['optname'] = ""
	end

	luci.http.prepare_content("application/json")
    luci.http.write_json(n)
end

function file_view()
	require "luci.template"
	require 'luci.sys'
	require 'luci.http'

	local files = ""
	local filesName = ""
	local status = ""

	local content = luci.sys.exec('/usr/local/localshell/usbdevice')

	if content ~= "" then
	
		local o = Split(content,'/////')

		if "NULL" ~= o[3] then
			status = 'Mounted'
			filesName = o[1]

			files = luci.sys.exec('/usr/local/localshell/usbdir BASE')
			local fileall ={}
			fileall = Split(files,"||||")
			table.remove(fileall)
			files = fileall
		end
	end

	luci.template.render("admin_web/fileview",{filecontent=files,flag=status,filename=filesName},nil)
end

function fileviewlist()
	require "luci.template"
	require "luci.http"
	require "luci.sys"

	local path = luci.http.formvalue("path")
	local files = ""

	if path == "" then
		files = luci.sys.exec('/usr/local/localshell/usbdir BASE')
	else
		files = luci.sys.exec('/usr/local/localshell/usbdir DIR '..path)
	end

	local fileall ={}
	fileall = Split(files,"||||")
	table.remove(fileall)
	files = fileall	

	luci.template.render("admin_web/fileviewlist",{filecontent=files})
end
