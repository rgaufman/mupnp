#! /usr/bin/ruby
# This module is a binding to the Thomas Bernard miniupnp library
# written in C.  It supports the IGD specification and works with IPv4
# only.  Every exception that comes from inside the library is report as
# UPnPException while wrong arguments are returned as ArgumentError.
#
# Author:: Dario Meloni (mailto:mellon85@gmail.com)
# License:: LGPL

require 'MiniUPnP'

module UPnP
  # Represent a port mapping decriptor received from the router.
  class PortMapping
    # Internal address.
    attr_reader :client
    # Internal port.
    attr_reader :lport
    # External port.
    attr_reader :nport
    # External protocol.
    attr_reader :protocol
    # Provided description.
    attr_reader :description
    # Is the mapping enabled?.
    attr_reader :enabled
    # Don't know ...
    attr_reader :rhost
    # Duration of the binding.
    attr_reader :duration

    def initialize(cl, lp, np, p, d, e, rh, du)
      @client = cl
      @lport = lp
      @nport = np
      @protocol = p
      @description = d
      @enabled = e
      @rhost = rh
      @duration = du
    end

    def to_s()
      "#{@nport}->#{@client}:#{@lport} #{@protocol} for #{@duration} -- #{@description}"
    end
  end

  # Enumeration of protocol values to pass to the library.
  class Protocol
    TCP = 'TCP'
    UDP = 'UDP'
  end

  # Represents an exception from inside the library.
  class UPnPException < StandardError
  end

  # The UPNP class represent the binding to the library.  It exports
  # all the functions the library itself exports.
  class UPnP
    # Max time to wait for a broadcast answer from the routers.
    attr_reader :max_wait_time
    # This will create a new UPnP instance.  max_wait is the maximum
    # time the instance will wait for an answer from the router
    # while seaching or it autodiscover to true will start a thread
    # on the background to scan the network.  All the other
    # functions are safe to be called in the meanwhile, they will
    # just wait for the scan to end before operating.
    # The variable sameport if set to true will receive UPnP answers from
    # the incoming port. It can be usefull with some routers.  Try with
    # false, and if it fails try again with true if the firewall allows
    # only UPnP ports.

    def initialize(autodiscover = true, sameport = true, max_wait = 1000)
      raise ArgumentError, 'Max wait time must be >= 1.' if max_wait <= 0

      if !(autodiscover == true) && !(autodiscover == false)
        raise ArgumentError, 'Autodiscover must be a boolean value.'
      end

      @max_wait_time = max_wait
      # start the discover process at the object initialization.
      # until ruby2, this thread will block the ruby environment
      # for the wait time.

      @sameport = sameport

      @igd_thread = autodiscover ? Thread.new { discoverIGD } : nil
    end

    # This method will search for other routers in the network and
    # will wait the specified number of milliseconds that can be
    # ovveridden by the parameter.  It has currently (ruby 1.9) a
    # limitation. As long as thread are cooperative the upnpDiscover
    # function will block the ruby implementation waiting for the
    # library.  If this will not be solved with ruby 2.0 the
    # interface upnp_wrap.c needs to be hacked.  You can avoid to
    # call this function if autodiscover is true.  If no router or
    # no UPnP devices are found an UPnPException is thrown.
    def discoverIGD(max_wait_time = @max_wait_time)
      joinThread
      raise ArgumentError, 'Max wait time must be >= 1' if max_wait_time <= 0

      sameport = @sameport != false ? 1 : 0
      @list = MiniUPnP.upnpDiscover(max_wait_time, nil, nil, sameport)

      raise UPnPException.new, 'No UPNP Device Found' if @list == nil

      ObjectSpace.define_finalizer(
        @list,proc { |o| MiniUPnP.freeUPNPDevlist(o) }
      )

      @urls = MiniUPnP::UPNPUrls.new
      ObjectSpace.define_finalizer(@urls,proc { |o| MiniUPnP.FreeUPNPUrls(o) })
      @data = MiniUPnP::IGDdatas.new
      @lan = getCString
      r = MiniUPnP.UPNP_GetValidIGD(@list, @urls, @data, @lan, 64)

      raise UPnPException.new, 'No IGD Found' if [0, 3].include?(r)

      @lan = @lan.rstrip
    end

    # Returns the ip of this client
    def lanIP
      joinThread
      @lan
    end

    # Returns the external network ip
    def externalIP
      joinThread
      external_ip = getCString
      r = MiniUPnP.UPNP_GetExternalIPAddress(
        @urls.controlURL, @data.servicetype,external_ip
      )

      if r != 0
        raise UPnPException.new, "Error while retriving the external ip address. #{code2error(r)}."
      end

      external_ip.rstrip
    end

    # Returns the ip of the router
    def routerIP
      joinThread
      @data.urlbase.sub(/^.*\//, '').sub(/\:.*/, '')
    end

    # Returns the status of the router which is an array of 3 elements.
    # Connection status, Last error, Uptime.
    def status
      joinThread
      lastconnerror = getCString
      status = getCString
      uptime = 0

      begin
        uptime_uint = MiniUPnP.new_uintp
        r = MiniUPnP.UPNP_GetStatusInfo(
          @urls.controlURL, @data.servicetype, status, uptime_uint, lastconnerror
        )

        if r != 0
          raise UPnPException.new, "Error while retriving status info. #{code2error(r)}."
        end

        uptime = MiniUPnP.uintp_value(uptime_uint)
      ensure
        MiniUPnP.delete_uintp(uptime_uint)
      end

      [status.rstrip, lastconnerror.rstrip, uptime]
    end

    # Router connection information
    def connectionType
      joinThread
      type = getCString
      if MiniUPnP.UPNP_GetConnectionTypeInfo(@urls.controlURL, @data.servicetype,type) != 0
        raise UPnPException.new, 'Error while retriving connection info.'
      end

      type.rstrip
    end

    # Total bytes sent from the router to external network
    def totalBytesSent
      joinThread
      v = MiniUPnP.UPNP_GetTotalBytesSent(
        @urls.controlURL_CIF, @data.servicetype_CIF
      )

      raise UPnPException.new, 'Error while retriving total bytes sent.' if v < 0

      v
    end

    # Total bytes received from the external network.
    def totalBytesReceived
      joinThread
      v = MiniUPnP.UPNP_GetTotalBytesReceived(
        @urls.controlURL_CIF, @data.servicetype_CIF
      )
      
      raise UPnPException.new, 'Error while retriving total bytes received.' if v < 0
      v
    end

    # Total packets sent from the router to the external network.
    def totalPacketsSent
      joinThread
      v = MiniUPnP.UPNP_GetTotalPacketsSent(
        @urls.controlURL_CIF, @data.servicetype_CIF
      )
      
      raise UPnPException.new, 'Error while retriving total packets sent.' if v < 0
      v
    end

    # Total packets received from the router from the external network.
    def totalPacketsReceived
      joinThread
      v = MiniUPnP.UPNP_GetTotalBytesSent(
        @urls.controlURL_CIF, @data.servicetype_CIF
      )
      
      raise UPnPException.new, 'Error while retriving total packets received.' if v < 0
      v
    end

    # Returns the maximum bitrates detected from the router (may be an
    # ADSL router) The result is in bytes/s.
    def maxLinkBitrates
      joinThread
      up, down = 0, 0

      begin
        up_p = MiniUPnP.new_uintp
        down_p = MiniUPnP.new_uintp
        if MiniUPnP.UPNP_GetLinkLayerMaxBitRates(@urls.controlURL_CIF, @data.servicetype_CIF, down_p,up_p) != 0
          raise UPnPException.new, 'Error while retriving maximum link bitrates.'
        end

        up = MiniUPnP.uintp_value(up_p)
        down = MiniUPnP.uintp_value(down_p)
      ensure
        MiniUPnP.delete_uintp(up_p)
        MiniUPnP.delete_uintp(down_p)
      end

      [down, up]
    end

    # An array of mappings registered on the router
    def portMappings
      joinThread
      i, r = 0, 0
      mappings = []

      while r == 0
        rhost = getCString
        enabled = getCString
        duration = getCString
        description = getCString
        nport = getCString
        lport = getCString
        duration = getCString
        client = getCString
        protocol = getCString

        r = MiniUPnP.UPNP_GetGenericPortMappingEntry(
          @urls.controlURL, @data.servicetype, i.to_s, nport, client, lport,
          protocol, description, enabled, rhost, duration
        )

        break if r != 0

        i += 1
        mappings << PortMapping.new(
          client.rstrip, lport.rstrip.to_i, nport.rstrip.to_i, protocol.rstrip,
          description.rstrip, enabled.rstrip, rhost.rstrip, duration.rstrip
        )
      end

      mappings
    end

    # Get the mapping registered for a specific port and protocol
    def portMapping(nport, proto)
      checkProto(proto)
      checkPort(nport)

      if nport.to_i == 0
        raise ArgumentError, 'Port must be an int value and greater then 0.'
      end

      joinThread
      client = getCString
      lport = getCString

      if MiniUPnP.UPNP_GetSpecificPortMappingEntry(@urls.controlURL, @data.servicetype, nport.to_s,proto, client,lport) != 0
        raise UPnPException.new, 'Error while retriving the port mapping.'
      end

      [client.rstrip, lport.rstrip.to_i]
    end

    # Add a port mapping on the router.  Parametes are: network
    # port, local port, description, protocol, ip address to
    # register (or do not specify it to register for yours).
    # Protocol must be Protocol::TCP or Protocol::UDP
    def addPortMapping(nport, lport, proto, desc, client = nil)
      checkProto(proto)
      checkPort(nport)
      checkPort(lport)
      joinThread
      client ||= @lan if client == nil

      r = MiniUPnP.UPNP_AddPortMapping(
        @urls.controlURL, @data.servicetype, nport.to_s, lport.to_s, client,
        desc, proto
      )

      raise UPnPException.new , "Failed add mapping: #{code2error(r)}." if r != 0
    end

    # Delete the port mapping for specified network port and protocol
    def deletePortMapping(nport, proto)
      checkProto(proto)
      checkPort(nport)
      joinThread
      r = MiniUPnP.UPNP_DeletePortMapping(
        @urls.controlURL,@data.servicetype, nport.to_s,proto
      )

      raise UPnPException.new, "Failed delete mapping: #{code2error(r)}." if r != 0
    end

    private

    # Generates an empty string to use with the library
    def getCString(len = 128)
      "\0" * len
    end

    # Method to wait until the scan is complete
    def joinThread
      @igd_thread.join if @igd_thread != nil && Thread.current != @igd_thread        
    end

    # Check that the protocol is a correct value
    def checkProto(proto)
      if proto != Protocol::UDP && proto != Protocol::TCP
        raise ArgumentError, "Unknown protocol #{proto}, only Protocol::TCP and Protocol::UDP are valid."
      end
    end

    def checkPort(port)
      iport = port.to_i
      if port.to_i != port || iport < 1 || iport > 65_535
        raise ArgumentError, 'Port must be an integer beetween 1 and 65,535.'
      end
    end

    def code2error(code)
      case code
      when 402
        '402 Invalid Args'
      when 501
        '501 Action Failed'
      when 713
        '713 SpecifiedArrayIndexInvalid - The specified array index is out of bounds'
      when 714
        '714 NoSuchEntryInArray - The specified value does not exist in the array'
      when 715
        '715 WildCardNotPermittedInSrcIP - The source IP address cannot be wild-carded'
      when 716
        '716 WildCardNotPermittedInExtPort - The external port cannot be wild-carded'
      when 718
        '718 ConflictInMappingEntry - The port mapping entry specified conflicts with a mapping assigned previously to another client'
      when 724
        '724 SamePortValuesRequired - Internal and External port values must be the same'
      when 725
        '725 OnlyPermanentLeasesSupported - The NAT implementation only supports permanent lease times on port mappings'
      when 726
        '726 RemoteHostOnlySupportsWildcard - RemoteHost must be a wildcard and cannot be a specific IP address or DNS name'
      when 727
        '727 ExternalPortOnlySupportsWildcard - ExternalPort must be a wildcard and cannot be a specific port value'
      else
        "Unknown Error - #{code2error(r)}"
      end
    end
  end
end
