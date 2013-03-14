require 'puppet/provider/firewall'
require 'digest/md5'

Puppet::Type.type(:firewall).provide :iptables, :parent => Puppet::Provider::Firewall do
  include Puppet::Util::Firewall

  @doc = "Iptables type provider"

  has_feature :iptables
  has_feature :rate_limiting
  has_feature :snat
  has_feature :dnat
  has_feature :interface_match
  has_feature :icmp_match
  has_feature :owner
  has_feature :state_match
  has_feature :recent_match
  has_feature :reject_type
  has_feature :log_level
  has_feature :log_prefix
  has_feature :mark
  has_feature :tcp_flags
  has_feature :pkttype
  has_feature :socket

  optional_commands({
    :iptables => '/sbin/iptables',
    :iptables_save => '/sbin/iptables-save',
  })

  defaultfor :kernel => :linux

  iptables_version = Facter.fact('iptables_version').value
  if (iptables_version and Puppet::Util::Package.versioncmp(iptables_version, '1.4.1') < 0)
    mark_flag = '--set-mark'
  else
    mark_flag = '--set-xmark'
  end

  @protocol = "IPv4"

  @resource_map = {
    :burst => "--limit-burst",
    :destination => "-d",
    :dport => ["-m multiport --dports", "-m (udp|tcp) --dport"],
    :gid => "-m owner --gid-owner",
    :icmp => "-m icmp --icmp-type",
    :iniface => "-i",
    :jump => "-j",
    :limit => "-m limit --limit",
    :log_level => "--log-level",
    :log_prefix => "--log-prefix",
    :name => "-m comment --comment",
    :outiface => "-o",
    :port => '-m multiport --ports',
    :proto => "-p",
    :reject => "--reject-with",
    :set_mark => mark_flag,
    :recent_command => '-m recent',
    :recent_set => "-m recent --set",
    :recent_update => "-m recent --update",
    :recent_remove => "-m recent --remove",
    :recent_rcheck => "-m recent --rcheck",
    :recent_name => "--name",
    :recent_rsource => "--rsource",
    :recent_rdest => "--rdest",
    :recent_seconds => "--seconds",
    :recent_hitcount => "--hitcount",
    :recent_rttl => "--rttl",
    :socket => "-m socket",
    :source => "-s",
    :sport => ["-m multiport --sports", "-m (udp|tcp) --sport"],
    :state => "-m state --state",
    :table => "-t",
    :tcp_flags => "-m tcp --tcp-flags",
    :todest => "--to-destination",
    :toports => "--to-ports",
    :tosource => "--to-source",
    :uid => "-m owner --uid-owner",
    :pkttype => "-m pkttype --pkt-type"
  }

  # Create property methods dynamically
  (@resource_map.keys << :chain << :table << :action).each do |property|
    define_method "#{property}" do
      @property_hash[property.to_sym]
    end

    define_method "#{property}=" do |value|
      @property_hash[:needs_change] = true
    end
  end

  # This is the order of resources as they appear in iptables-save output,
  # we need it to properly parse and apply rules, if the order of resource
  # changes between puppet runs, the changed rules will be re-applied again.
  # This order can be determined by going through iptables source code or just tweaking and trying manually
  @resource_list = [:table, :source, :destination, :iniface, :outiface,
    :proto, :tcp_flags, :gid, :uid, :sport, :dport, :port, :socket, :pkttype, :name, :state, :icmp, :limit, :burst,
    :recent_update, :recent_set, :recent_rcheck, :recent_remove, :recent_seconds, :recent_hitcount,
    :recent_rttl, :recent_name, :recent_rsource, :recent_rdest,
    :jump, :todest, :tosource, :toports, :log_level, :log_prefix, :reject, :set_mark]
  @resource_list_noargs = [:recent_set, :recent_update, :recent_rcheck,
    :recent_remove, :recent_rsource, :recent_rdest, :socket]

  def insert
    debug 'Inserting rule %s' % resource[:name]
    iptables insert_args
  end

  def update
    debug 'Updating rule  %s' % resource[:name]
    iptables update_args
  end

  def delete
    debug 'Deleting rule %s' % resource[:name]
    iptables delete_args
  end

  def exists?
    properties[:ensure] != :absent
  end

  # Flush the property hash once done.
  def flush
    debug("[flush]")
    if @property_hash.delete(:needs_change)
      notice("Properties changed - updating rule")
      update
    end
    persist_iptables(self.class.instance_variable_get(:@protocol))
    @property_hash.clear
  end

  def self.instances
    debug "[instances]"
    table = nil
    rules = []
    counter = 1

    # String#lines would be nice, but we need to support Ruby 1.8.5
    iptables_save.split("\n").each do |line|
      unless line =~ /^\#\s+|^\:\S+|^COMMIT|^FATAL/
        if line =~ /^\*/
          table = line.sub(/\*/, "")
        else
          if hash = rule_to_hash(line, table, counter)
            rules << new(hash)
            counter += 1
          end
        end
      end
    end
    rules
  end

  def self.rule_to_hash(line, table, counter)
    hash = {}
    keys = []
    values = line.dup

    # These are known booleans that do not take a value, but we want to munge
    # to true if they exist.
    known_booleans = @resource_list_noargs.nil? ? [ ] : @resource_list_noargs

    ####################
    # PRE-PARSE CLUDGING
    ####################

    # --tcp-flags takes two values; we cheat by adding " around it
    # so it behaves like --comment
    values = values.sub(/--tcp-flags (\S*) (\S*)/, '--tcp-flags "\1 \2"')

    # Trick the system for booleans
    known_booleans.each do |bool|
      values = values.sub(/#{@resource_map[bool]}/,
                          "#{@resource_map[bool]} true")
    end

    ############
    # MAIN PARSE
    ############

    # Here we iterate across our values to generate an array of keys
    @resource_list.reverse.each do |k|
      resource_map_key = @resource_map[k]
      [resource_map_key].flatten.each do |opt|
        if values.slice!(/\s#{opt}/)
          keys << k
          break
        end
      end
    end

    # Manually remove chain
    values.slice!('-A')
    keys << :chain

    # Here we generate the main hash
    keys.zip(values.scan(/"[^"]*"|\S+/).reverse) { |f, v| hash[f] = v.gsub(/"/, '') }

    #####################
    # POST PARSE CLUDGING
    #####################

    # Normalise all rules to CIDR notation.
    [:source, :destination].each do |prop|
      hash[prop] = Puppet::Util::IPCidr.new(hash[prop]).cidr unless hash[prop].nil?
    end

    [:dport, :sport, :port, :state].each do |prop|
      hash[prop] = hash[prop].split(',') if ! hash[prop].nil?
    end

    # Convert booleans removing the previous cludge we did
    known_booleans.each do |bool|
      if hash[bool] != nil then
        if hash[bool] == "true" then
          hash[bool] = true
        else
          raise "Parser error: #{bool} was meant to be a boolean but received value: #{hash[bool]}."
        end
      end
    end

    # Our type prefers hyphens over colons for ranges so ...
    # Iterate across all ports replacing colons with hyphens so that ranges match
    # the types expectations.
    begin
      [:dport, :sport, :port].each do |prop|
        next unless hash[prop]
        hash[prop] = hash[prop].collect do |elem|
          elem.gsub(/:/,'-')
        end
      end
    rescue => exp
      puts "Error at range delimiting: " + exp
      raise
    end

    # States should always be sorted. This ensures that the output from
    # iptables-save and user supplied resources is consistent.
    hash[:state] = hash[:state].sort unless hash[:state].nil?

    # This forces all existing, commentless rules to be moved to the bottom of the stack.
    # Puppet-firewall requires that all rules have comments (resource names) and will fail if
    # a rule in iptables does not have a comment. We get around this by appending a high level
    if ! hash[:name]
      hash[:name] = "9999 #{Digest::MD5.hexdigest(line)}"
    end

    # Iptables defaults to log_level '4', so it is omitted from the output of iptables-save.
    # If the :jump value is LOG and you don't have a log-level set, we assume it to be '4'.
    if hash[:jump] == 'LOG' && ! hash[:log_level]
      hash[:log_level] = '4'
    end

    # Handle recent module
    hash[:recent_command] = :set if hash.include?(:recent_set)
    hash[:recent_command] = :update if hash.include?(:recent_update)
    hash[:recent_command] = :remove if hash.include?(:recent_remove)
    hash[:recent_command] = :rcheck if hash.include?(:recent_rcheck)

    [:recent_set, :recent_update, :recent_remove, :recent_rcheck].each do |key|
      hash.delete(key)
    end

    # rsource is the default if rdest isn't set and recent is being used
    hash[:recent_rsource] = true if \
        hash.key?:recent_command and ! hash[:recent_rdest]

    hash[:line] = line
    hash[:provider] = self.name.to_s
    hash[:table] = table
    hash[:ensure] = :present

    # Munge some vars here ...

    # Proto should equal 'all' if undefined
    hash[:proto] = "all" if !hash.include?(:proto)

    # If the jump parameter is set to one of: ACCEPT, REJECT or DROP then
    # we should set the action parameter instead.
    if ['ACCEPT','REJECT','DROP'].include?(hash[:jump]) then
      hash[:action] = hash[:jump].downcase
      hash.delete(:jump)
    end

    hash
  end

  def insert_args
    args = []
    args << ["-I", resource[:chain], insert_order]
    args << general_args
    args
  end

  def update_args
    args = []
    args << ["-R", resource[:chain], insert_order]
    args << general_args
    args
  end

  def delete_args
    count = []
    begin
      line = properties[:line].gsub(/(^|\s+)-A\s+/, '\\1-D ').split
    rescue => exp
      puts "Error at delete_args(): " + exp
      raise
    end

    # Grab all comment indices
    line.each do |v|
      if v =~ /"/
        count << line.index(v)
      end
    end

    # Merge the quoted comments/etc into one element
    count.reverse!
    while ! count.empty?
      startidx = count.pop
      stopidx  = count.pop
      line[startidx] = line[startidx..stopidx].join(' ').gsub(/"/, '')
      ((startidx + 1)..stopidx).each do |i|
        line[i] = nil
      end
    end

    line.unshift("-t", properties[:table])

    # Return array without nils
    line.compact
  end

  # This method takes the resource, and attempts to generate the command line
  # arguments for iptables.
  def general_args
    debug "Current resource: %s" % resource.class

    args = []
    resource_list = self.class.instance_variable_get('@resource_list')
    resource_list_noargs = self.class.instance_variable_get('@resource_list_noargs')
    resource_map = self.class.instance_variable_get('@resource_map')
    resource_list_recent_commands = [:recent_set, :recent_update, :recent_rcheck, :recent_remove]

    resource_list.each do |res|
      resource_value = nil
      if !(resource_list_recent_commands.include?(res)) then
        if (resource[res]) then
          resource_value = resource[res]
          if resource_list_noargs.include?(res) then
            resource_value = nil
          end
        elsif res == :jump and resource[:action] then
          # In this case, we are substituting jump for action
          resource_value = resource[:action].to_s.upcase
        else
          next
        end
      end

      what = res.to_s.scan(/^recent_(\w+)/)
      if ! what.empty?
        # only append recent_ args if there is a recent_command
        if ! (resource['recent_command'])
          next
        end
        # only append the right recent_ command
        if resource_list_recent_commands.include?(res) and \
            resource['recent_command'].to_s != what[0][0]
          next
        end
        # only append rsource/rdest if set
        if res == :recent_rsource and not resource['recent_rsource']:
          next
        end
        if res == :recent_rdest and not resource['recent_rdest']:
          next
        end
      end

      args << [resource_map[res]].flatten.first.split(' ')

      # For sport and dport, convert hyphens to colons since the type
      # expects hyphens for ranges of ports.
      begin
        if [:sport, :dport, :port].include?(res) then
          resource_value = resource_value.collect do |elem|
            elem.gsub(/-/, ':')
          end
        end
      rescue => exp
        puts "Error at general_args(): " + exp
        raise
      end

      if !resource_list_noargs.include?(res) then
        # our tcp_flags takes a single string with comma lists separated
        # by space
        # --tcp-flags expects two arguments
        if res == :tcp_flags
          one, two = resource_value.split(' ')
          args << one
          args << two
        elsif resource_value.is_a?(Array)
          args << resource_value.join(',')
        else
          args << resource_value
        end
      end
    end

    args
  end

  def insert_order
    debug("[insert_order]")
    rules = []

    # Find list of current rules based on chain and table
    self.class.instances.each do |rule|
      if rule.chain == resource[:chain].to_s and rule.table == resource[:table].to_s
        rules << rule.name
      end
    end

    # No rules at all? Just bail now.
    return 1 if rules.empty?

    my_rule = resource[:name].to_s
    rules << my_rule
    rules.sort.index(my_rule) + 1
  end
end
