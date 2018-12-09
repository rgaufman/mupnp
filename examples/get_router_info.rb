#!/usr/bin/ruby

require 'rubygems'
require 'UPnP'

begin
  u = UPnP::UPnP.new
  puts "Internet IP #{u.external_ip}"
  puts "Router Lan IP #{u.router_ip}"
  dn, up = u.max_link_bitrates
  puts "Max Link Bitrate #{dn}/#{up}"
  s, e, ut = u.status 
  puts "Status #{s}"
  puts "Uptime #{ut}"
  puts "Connection type #{u.connection_type}"
rescue UPnP::UPnPException
  puts "UPnP Exception occourred #{$ERROR_INFO}"
rescue
  puts $ERROR_INFO
end
