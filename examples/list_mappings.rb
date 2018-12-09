#!/usr/bin/ruby

require 'rubygems'
require 'UPnP'

begin
  u = UPnP::UPnP.new
  u.port_mappings.each do |o|
    puts o.to_s
  end
rescue UPnP::UPnPException
  puts "UPnP Exception occourred #{$ERROR_INFO}"
rescue
  puts $ERROR_INFO
end
