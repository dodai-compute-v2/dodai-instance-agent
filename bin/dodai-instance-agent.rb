#!/mnt/.dodai/.rbenv/shims/ruby

# Copyright 2013 National Institute of Informatics.
#
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


require 'rubygems'
require 'sinatra/base'
require 'json'
require 'open-uri'
require 'logger'

class DodaiInstanceAgentConfig

	@@dodai_env = {}
	@@dodai_env[:root] = '/mnt/.dodai'
	@@dodai_env[:etc] = "#{@@dodai_env[:root]}/etc"
	@@dodai_env[:log] = "#{@@dodai_env[:root]}/dodai-instance-agent.log"
	@@err_msg = {}
	@@err_msg[:e404] = "Not Found"
	@@err_msg[:e500] = "Internal Server Error"
	@@logger = Logger.new(@@dodai_env[:log])

	def get_variables
		return {:dodai_env => @@dodai_env, :err_msg => @@err_msg}
	end

	def get_system_ip(config = load_config)
		config['interfaces'].each do |interface|
			return interface['ip_address'] if 'system' == interface['role']
		end
	end

	def load_config(config_file = "#{@@dodai_env[:etc]}/dodai.json")
		@@logger.debug "config_file = #{@@dodai_env[:etc]}/dodai.json"
		if File.exist?(config_file)
			begin
				config_size = `ls -l #{config_file}`
				@@logger.debug "load_config: before read config: #{config_size}"
				config_data = File.open(config_file, 'r').read
				config_size = `ls -l #{config_file}`
				@@logger.debug "load_config: after read config: #{config_size}"
				@@logger.debug "contents of config_file: #{config_data}"
				config = JSON.parse(config_data)
			rescue
				@@logger.debug "Cannot read file #{config_file}"
			end
		else
			config = {
				:bind_port => 60601,
				:state => 'deploying',
				:interfaces => [
					{:name => 'eth0',
					:mac_address => '00:00:00:00:00:00',
					:ip_address => '0.0.0.0',
					:netmask => '0.0.0.0',
					:role => 'system',
					},
				],
				:metadata_server => ''
			}
			config = JSON.parse(config.to_json)
		end
		return config
	end

	def save_config(config, config_file = "#{@@dodai_env[:etc]}/dodai.json")
		@@logger.debug "save_config: contents of config: #{config}"
		if config and 0 < config.size
			config_size = `ls -l #{config_file}`
			@@logger.debug "save_config: before save config: #{config_size}"
			File.open(config_file, 'w') do |file|
				file.puts config.to_json
			end
			config_size = `ls -l #{config_file}`
			@@logger.debug "save_config: after save config: #{config_size}"
		end
	end
end

class DodaiInstanceAgent < Sinatra::Base
	disable :logging
	enable :lock
	set :server, "webrick"

	@@dodai_instance_agent_config = DodaiInstanceAgentConfig.new
	@@config = @@dodai_instance_agent_config.load_config
	variables = @@dodai_instance_agent_config.get_variables
	@@dodai_env = variables[:dodai_env]
	@@err_msg = variables[:err_msg]
	@@logger = Logger.new(@@dodai_env[:log])

	# NOTE: floating_ip is reset by reboot, so force to add
	agent_config = @@dodai_instance_agent_config.load_config
	agent_config['interfaces'].each do |interface|
		next unless /^floating_ip_[0-9]*/ =~ interface['role']
		@@logger.debug "initialize: force to add ip addr #{interface['name']}"
		result = IO.popen("ip addr add #{interface['ip_address']} dev #{interface['name']}", 'r').gets
	end

	def mac_to_nic(mac)
		nic = ''
		@@logger.debug "mac_to_nic: has bond?: #{IO.popen('ifconfig -a | grep ^bond | wc -l', 'r').gets}"
		if 0 < IO.popen('ifconfig -a | grep ^bond | wc -l', 'r').gets.chomp.to_i
			File.open('/proc/net/bonding/bond0', 'r').read.each_line do |line|
				if /^Slave Interface: (.*)$/ =~ line
					nic = $1.chomp
				elsif /^Permanent HW addr: (.*)$/ =~ line
					if $1.chomp.downcase ==  mac.downcase
						return nic
					end
				end
			end
			return IO.popen("ifconfig -a | grep -i #{mac} | awk '{print $1}'", 'r').gets.chomp
		else
			result = IO.popen("ifconfig -a | grep -i #{mac}", 'r').gets
			@@logger.debug "mac_to_nic: has #{mac}?: #{result}"
			return IO.popen("ifconfig -a | grep -i #{mac} | awk '{print $1}'", 'r').gets.chomp
		end
	end

	def mac_to_nic_by_udev_rule(mac)
		nic = ''
		File.open('/mnt/sda2/etc/udev/rules.d/70-persistent-net.rules', 'r') do |file|
			file.each_line do |line|
				rules = {}
				next if '#' == line[0,1]
				next if 0 == line.chomp.size
				line = line.gsub(/\s/, '').gsub(/"/, '')
				line.split(',').each do |str|
					if str.include?('=')
						array = str.split('=')
						rules[array[0]] = array[-1]
					end
				end
				next if 0 == rules.size
				if rules['ATTR{address}'].downcase == mac.downcase and rules['SUBSYSTEM'] == 'net' and rules['ACTION'] == 'add'
					nic = rules['NAME']
					break
				end
			end
		end
		return nic
	end

	def nic_to_mac(nic)
		return IO.popen("ifconfig #{nic} | grep HWaddr | awk '{print $5}'", 'r').gets.chomp
	end

	def get_state
		config = @@dodai_instance_agent_config.load_config
		return config['state']
	end

	def get_power
		return "on"
	end

	def set_power(params)
		result = ''
		case params[:action]
		when "reboot"
			if params.include?(:debug)
				result = 'shutdown -r +1'
			else
				result = IO.popen('shutdown -r +1', 'r').gets.chomp
			end
		when "shutdown"
			if params.include?(:debug)
				result = 'shutdown -h +1'
			else
				result = IO.popen('shutdown -h +1', 'r').gets.chomp
			end
		end
		return result
	end

	def get_ec2_metadata(key = '/')
		metadata = {}
		base = 'http://169.254.169.254/latest/meta-data'
		open("#{base}#{key}").each_line do |line|
			line.chomp! if line
			if %r|.*/$| =~ line
				metadata.merge!(get_ec2_metadata("#{key}#{line}"))
			elsif %r|.*=.*$| =~ line
				child_key = line.split('=')[0] + '/'
				metadata.merge!(get_ec2_metadata("#{key}#{child_key}"))
			elsif line
				value = open("#{base}#{key}#{line}").read
				value.chomp! if value
				metadata.merge!({"#{key}#{line}" => value})
			end
		end
		return metadata
	end

	def get_openstack_metadata(auth_token, instance_id, metadata_server, tenant_id)
		request = "http://#{metadata_server}/v2/#{tenant_id}/servers/#{instance_id}/metadata"
		header = {'X-Auth-Token' => auth_token, 'Content-type' => 'application/json'}
		metadata = JSON.parse(open(request, header).read)
		return metadata
	end

	def get_distro_info(root_path = '')
		name = 'unknown'
		version = 'unknown'
		redhat_release = "#{root_path}/etc/redhat-release"
		gentoo_release = "#{root_path}/etc/gentoo-release"
		lsb_release = "#{root_path}/etc/lsb-release"
		lsb_release_cmd = IO.popen('which lsb_release', 'r').gets.to_s.chomp
		if 0 < lsb_release_cmd.size
			name = IO.popen("#{lsb_release_cmd} -i", 'r').gets.chomp.split(/\t/)[1]
			version = IO.popen("#{lsb_release_cmd} -r", 'r').gets.chomp.split(/\t/)[1]
		elsif File.exist?(lsb_release)
			name = version = ''
			File.open(lsb_release, 'r') do |file|
				file.each_line do |line|
				case line.chomp
				when /^DISTRIB_ID=(.*)/
					name = $1.downcase
				when /^DISTRIB_RELEASE=([0-9.]*)/
					version = $1
				end
			end
			end
		elsif File.exist?(redhat_release)
			case File.open(redhat_release, 'r').read.chomp
			when /^Red Hat Enterprise Linux.* ([0-9.]*) .*/
				name = 'rhel'
				version = $1
			when /^CentOS .* ([0-9.]*) .*/
				name = 'centos'
				version = $1
			end
		elsif File.exist?(gentoo_release)
			case File.open(gentoo_release, 'r').read.chomp
			when /^Gentoo Base System release ([0-9.]*)/
				name = 'gentoo'
				version = $1
			end
		end
		return {:name => name.downcase, :version => version}
	end

	def network_restart_rhel(version, params, metadata, root_path = '')
		result = ''
		if params.include?(:debug)
			result = '/etc/init.d/network restart'
		else
			result = IO.popen('/etc/init.d/network restart', 'r').gets.chomp
		end
		return result
	end

	def network_restart_centos(version, params, metadata, root_path = '')
		return network_restart_rhel(version, params, metadata)
	end

	def set_networks_rhel(version, params, metadata, root_path = '')
		mac_addresses = []
		dns = []
		metadata.each do |k, m|
			next unless k.include?(%r|^(floating\|fixed)_ip_[0-9]*|)
			mac_addresses << m['mac_address']
			m['dnsnameservers'].each do |key, value|
				dns << value
			end
		end
		mac_addresses.sort!
		metadata.each do |k, m|
			next unless k.include?(%r|^(floating\|fixed)_ip_[0-9]*|)
			if mac_addresses[0].downcase == m['mac_address'].downcase and m['gateway_ip']
				gateway = %Q(GATEWAY="#{m['gateway_ip']}")
			else
				gateway = ''
			end
			nic = mac_to_nic(m['mac_address'])
			file_name = "/etc/sysconfig/network-scripts/ifcfg-#{nic}"
			if params.include?(:debug)
				file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
			end
			File.open(file_name, 'w') do |file|
				file.puts <<-EOL
DEVICE="#{nic}"
BOOTPROTO="static"
ONBOOT="yes"
NM_CONTROLLED="no"
IPADDR="#{m['ip_address']}"
NETMASK="#{m['subnet_mask']}"
HWADDR="#{m['mac_address']}"
#{gateway}
				EOL
			end
			resolv = ''
			file_name = '/etc/resolv.conf'
			File.open(file_name, 'r').read.each_line do |line|
				resolv << line if /^nameserver.*/ !~ line
			end
			if params.include?(:debug)
				file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
			end
			File.open(file_name, 'w') do |file|
				resolv.each do |line|
					file.puts line
				end
				dns.each do |key, value|
					file.puts "nameserver #{value}"
				end
			end
		end
	end

	def set_networks_centos(version, params, metadata, root_path = '')
		return set_networks_rhel(version, params, metadata)
	end

	def set_networks_ubuntu(version, params, metadata, root_path = '')
		agent_config = @@dodai_instance_agent_config.load_config
		@@logger.debug "set_networks_ubuntu: agent_config: #{agent_config}"
		case metadata.keys[0]
		when /^fixed_ip_[0-9]*/
			mac_addresses = []
		config = <<-EOL
auto lo
iface lo inet loopback
		EOL
			@@logger.debug "set_networks_ubuntu: config: #{config}"
		agent_config['interfaces'].each do |interface|
			if 'system' == interface['role']
					if root_path.to_s == ''
						interface['name'] = mac_to_nic(interface['mac_address'])
					else
						interface['name'] = mac_to_nic_by_udev_rule(interface['mac_address'])
					end
				config += <<-EOL

auto #{interface['name']}
iface #{interface['name']} inet static
	address #{interface['ip_address']}
	netmask #{interface['netmask']}
			EOL
			end
		end
			@@logger.debug "set_networks_ubuntu: config: #{config}"
		config += <<-EOL

		EOL
			@@logger.debug "set_networks_ubuntu: metadata: #{metadata}"
		metadata.each do |k, m|
				next unless /^fixed_ip_[0-9]*/ =~ k
			mac_addresses << m['mac_address']
		end
			@@logger.debug "set_networks_ubuntu: config: #{config}"
		mac_addresses.sort!
		metadata.each do |k, m|
				next unless /^fixed_ip_[0-9]*/ =~ k
				@@logger.debug "set_networks_ubuntu: m['mac_address']: #{m['mac_address']}"
				if root_path.to_s == ''
			device_name = mac_to_nic(m['mac_address'])
				else
					device_name = mac_to_nic_by_udev_rule(m['mac_address'])
				end
				@@logger.debug "set_networks_ubuntu: device_name: #{device_name}"
				@@logger.debug "set_networks_ubuntu: mac_addresses[0]: #{mac_addresses[0]}"
				if mac_addresses[0].downcase == m['mac_address'].downcase and m['gateway_ip']
					gateway = "gateway #{m['gateway_ip']}"
			else
				gateway = ''
			end
				if m['dnsnameservers'] and 0 < m['dnsnameservers'].size
					dns = []
					m['dnsnameservers'].each do |ns|
						dns << ns['address'] if ns.has_key?('address')
					end
					dnsnameservers = "dns-nameservers #{dns.join(' ')}"
				else
					dnsnameservers = ''
				end
				ip_ids = []
				agent_config['interfaces'].each do |interface|
					next if interface['role'] == 'system'
					ip_ids << interface['role']
				end
				unless ip_ids.include?(k)
					agent_config['interfaces'] << {
						:name => device_name,
						:ip_address => m['ip_address'],
						:netmask => m['netmask'],
						:mac_address => m['mac_address'],
						:gateway => gateway,
						:dnsnameservers => dnsnameservers,
						:role => k,
					}
					@@dodai_instance_agent_config.save_config(agent_config)
				end
			config += <<-EOL

auto #{device_name}
iface #{device_name} inet static
	address #{m['ip_address']}
	netmask #{m['netmask']}
	#{gateway}
	#{dnsnameservers}
			EOL
		end
			@@logger.debug "set_networks_ubuntu: config: #{config}"
			file_name = "#{root_path}/etc/network/interfaces"
		if params.include?(:debug)
			file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
		end
		File.open(file_name, 'w') do |file|
			file.puts config
		end
=begin
		# NOTE: /etc/resolv.conf cannot be written by hand on Ubuntu 12.04LTS or above.
		resolv = ''
		file_name = "#{root_path}/etc/resolv.conf"
		File.open(file_name, 'r').read.each_line do |line|
			resolv << line if /^nameserver.*/ !~ line
		end
		if params.include?(:debug)
			file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
		end
		File.open(file_name, 'w') do |file|
			resolv.each do |line|
				file.puts line
			end
			dns.each do |address|
				file.puts "nameserver #{address}"
			end
		end
=end
		when /^floating_ip_[0-9]*/
			metadata.each do |k, m|
				next unless /^floating_ip_[0-9]*/ =~ k
				device_name = mac_to_nic(m['mac_address'])
				@@logger.debug "set_networks_ubuntu: device_name: #{device_name}"
				ip_ids = []
				agent_config['interfaces'].each do |interface|
					next if interface['role'] == 'system'
					ip_ids << interface['role']
				end
				unless ip_ids.include?(k)
					agent_config['interfaces'] << {
						:name => device_name,
						:ip_address => m['ip_address'],
						:mac_address => m['mac_address'],
						:role => k,
					}
					@@dodai_instance_agent_config.save_config(agent_config)
				end
				result = IO.popen("ip addr add #{m['ip_address']} dev #{device_name}", 'r').gets
			end
		end
		return true
	end

	def network_restart_ubuntu(version, params, metadata, root_path = '')
		result = ''
		metadata.each do |k, m|
			next unless /^fixed_ip_[0-9]*/ =~ k
			if root_path.to_s == ''
			nic = mac_to_nic(m['mac_address'])
			else
				nic = mac_to_nic_by_udev_rule(m['mac_address'])
			end
			if params.include?(:debug)
				result += "ifdown #{nic}\n"
			else
				@@logger.debug "network_restart_ubuntu: ifdown #{nic}"
				stdout = IO.popen("ifdown #{nic}", 'r').gets
				@@logger.debug "network_restart_ubuntu: ifdown #{nic} result: #{stdout}"
				result += stdout if stdout
			end
		end
		metadata.each do |k, m|
			next unless /^fixed_ip_[0-9]*/ =~ k
			if root_path.to_s == ''
			nic = mac_to_nic(m['mac_address'])
			else
				nic = mac_to_nic_by_udev_rule(m['mac_address'])
			end
			if params.include?(:debug)
				result += "ifup #{nic}\n"
			else
				@@logger.debug "network_restart_ubuntu: ifup #{nic}"
				stdout = IO.popen("ifup #{nic}", 'r').gets
				@@logger.debug "network_restart_ubuntu: ifup #{nic} result: #{stdout}"
				result += stdout if stdout
			end
		end
		@@logger.debug "network_restart_ubuntu: result: #{result}"
		return result
	end

	def set_networks(params)
		action = ''
		root_path = ''
		cmdline = File.open('/proc/cmdline', 'r').read
		root_fs_type = ''
		if /.* root_fs_type=(.*?) .*/ =~ cmdline
			root_fs_type = $1
		end
		case cmdline
		when /.* action=deploy .*/
			action = :deploy
			root_path = '/mnt/sda2'
			@@logger.debug "set_network: action=deploy"
			result = IO.popen("mount -t #{root_fs_type} /dev/sda2 /mnt/sda2", 'r').gets
		end
		distro = get_distro_info(root_path)
=begin
		openstack_metadata = get_openstack_metadata(
			params[:auth_token],
			params[:instance_id],
			params[:metadata_server],
			params[:tenant_id]
		)
=end
		@@logger.debug "set_networks: distro[:name]: #{distro[:name]}"
		@@logger.debug "set_networks: distro[:version]: #{distro[:version]}"
		openstack_metadata = params
		eval("set_networks_#{distro[:name]}(#{distro[:version]}, params, openstack_metadata, root_path)")
		eval("network_restart_#{distro[:name]}(#{distro[:version]}, params, openstack_metadata, root_path)")

		if :deploy == action
			result = IO.popen("umount /mnt/sda2", 'r').gets
		end
		return true
	end

	def delete_networks_ubuntu(version, floating_ip_id)
		interfaces = []
		result = ''
		agent_config = @@dodai_instance_agent_config.load_config
		@@logger.debug "delete_networks_ubuntu: agent_config: #{agent_config}"
		agent_config['interfaces'].each do |interface|
			if floating_ip_id == interface['role']
				nic = mac_to_nic(interface['mac_address'])
				@@logger.debug "delete_networks_ubuntu: nic: #{nic}"
				result = IO.popen("ip addr del #{interface['ip_address']} dev #{nic}", 'r').gets
				agent_config['interfaces'].delete(interface)
				@@dodai_instance_agent_config.save_config(agent_config)
				break
			end
		end
		@@logger.debug "delete_networks_ubuntu: agent_config: #{agent_config}"
		return true
	end

	def delete_networks(floating_ip_id)
		distro = get_distro_info
		@@logger.debug "delete_networks: distro[:name]: #{distro[:name]}"
		@@logger.debug "delete_networks: distro[:version]: #{distro[:version]}"
		@@logger.debug "eval('delete_networks_#{distro[:name]}(#{distro[:version]}, floating_ip_id)')"
		eval("delete_networks_#{distro[:name]}(#{distro[:version]}, floating_ip_id)")
	end

	def init_networks(params)
		mac_addresses = []
		udev_user = []
		udev_system = []
		distro = get_distro_info('/mnt/sda2/')
		IO.popen("ifconfig | grep HWaddr | awk '{print $1,$5}'", 'r').gets.each_line do |nic_info|
			nic, mac_address = nic_info.split(' ')
			mac_addresses << [mac_address, nic]
		end
		nic_number = 0
		mac_addresses.sort.each do |mac, nic|
			config_index = 0
			@config['interfaces'].each do |interface|
				if 'system' == interface['role'] and mac.downcase == interface['mac_address'].downcase
					udev_system << [mac, "eth#{nic_number}"]
					@config['interfaces'][config_index]['name'] = "eth#{nic_number}"
					config_index += 1
					nic_number += 1
				elsif mac.downcase == interface['mac_address'].downcase
					udev_user << [mac, "eth#{nic_number}"]
					nic_number += 1
				end
			end
		end
		udev = udev_user + udev_system
		save_config(@config)
		save_udev(udev)
	end

	def set_keypairs(params)
		@@logger.debug "set_keypairs: params: #{params}"
		public_key = ''
		if params.include?('public_key')
			public_key = params['public_key']
			@@logger.debug "set_keypairs: public_key with params: #{public_key}"
		else
			metadata = get_ec2_metadata
			public_key = metadata["/public-keys/0/openssh-key"]
			@@logger.debug "set_keypairs: public_key with ec2 metadata: #{public_key}"
		end
		file_name = '/root/.ssh/authorized_keys'
		action = ''
		cmdline = File.open('/proc/cmdline', 'r').read
		root_fs_type = ''
		if /.* root_fs_type=(.*?) .*/ =~ cmdline
			root_fs_type = $1
		end
		case cmdline
		when /.* action=deploy .*/
			action = :deploy
			@@logger.debug "set_keypairs: action=deploy"
			result = IO.popen("mount -t #{root_fs_type} /dev/sda2 /mnt/sda2", 'r').gets
			file_name = '/mnt/sda2' + file_name
			@@logger.debug "set_keypairs: file_name: #{file_name}"
		end
		if params.include?(:debug)
			file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
			@@logger.debug "set_keypairs: file_name: #{file_name}"
		end
		file_size=`ls -l #{file_name}`
		@@logger.debug "set_keypairs: file_size: #{file_size}"
		File.open(file_name, 'a') do |file|
			file.puts public_key
		end
		if :deploy == action
			result = IO.popen("umount /mnt/sda2", 'r').gets
		end
		return true
	end

	resource_path = '/services/dodai-instance'
	resources = {}
	resources[:networks] = "#{resource_path}/networks"
	resources[:key] = "#{resource_path}/key"
	resources[:state] = "#{resource_path}/state"
	resources[:power] = "#{resource_path}/power"

	get "#{resource_path}/variables" do
		content_type :json
		result = @@dodai_instance_agent_config.get_variables
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get "#{resource_path}/config" do
		content_type :json
		result = @@dodai_instance_agent_config.load_config
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get resources[:state] do
		content_type :json
		result = get_state
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get resources[:power] do
		content_type :json
		result = get_power
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put resources[:power] do
		content_type :json
		result = set_power(params)
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put resources[:key] do
		content_type :json
		@@logger.debug "put /#{resources[:key]} params: #{params}"
		request.body.rewind
		body = request.body.read
		if body
			data = JSON.parse(body)
			@@logger.debug "put /#{resources[:key]} data: #{data}"
			result = set_keypairs(data)
		else
		result = set_keypairs(params)
		end
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	delete "#{resources[:networks]}/:name" do
		content_type :json
		@@logger.debug "delete /networks/:name params: #{params}"
		result = delete_networks(params[:name])
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put resources[:networks] do
		content_type :json
		request.body.rewind
		data = JSON.parse(request.body.read)
		@@logger.debug "networks.json params: #{params}"
		@@logger.debug "networks.json data: #{data}"
		result = set_networks(data)
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

end

config = DodaiInstanceAgentConfig.new.load_config
bind_address = DodaiInstanceAgentConfig.new.get_system_ip(config)
p bind_address
p config['bind_port']
DodaiInstanceAgent.run! :bind => bind_address, :port => config['bind_port'].to_s

#vim: tabstop=3 shiftwidth=3 softtabstop=3
