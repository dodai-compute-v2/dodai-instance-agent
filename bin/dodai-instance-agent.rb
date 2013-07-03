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
require 'sinatra'
require 'json'
require 'open-uri'

class DodaiInstanceAgentConfig

	@@dodai_env = {}
	@@dodai_env[:root] = '/mnt/.dodai'
	@@dodai_env[:etc] = "#{@@dodai_env[:root]}/etc"
	@@dodai_env[:log] = "#{@@dodai_env[:root]}/log"
	@@err_msg = {}
	@@err_msg[:e404] = "Not Found"
	@@err_msg[:e500] = "Internal Server Error"

	def get_variables
		return {:dodai_env => @@dodai_env, :err_msg => @@err_msg}
	end

	def get_system_ip(config = load_config)
		config['interfaces'].each do |interface|
			return interface['ip_addresses'][0] if 'system' == interface['role']
		end
	end

	def load_config(config_file = "#{@@dodai_env[:etc]}/dodai.json")
		if File.exist?(config_file)
			config = JSON.parse(File.open(config_file, 'r').read)
		else
			config = {
				:bind_port => 60601,
				:state => 'deploying',
				:interfaces => [
					{:name => 'ethX',
					:mac_address => '00:00:00:00:00:00',
					:ip_addresses => ['0.0.0.0'],
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
		File.open(config_file, 'w').puts config.to_json
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

	def mac_to_nic(mac)
		nic = ''
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
			return IO.popen("ifconfig -a | grep -i #{mac} | awk '{print $1}'", 'r').gets.chomp
		end
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

	def get_distro_info(root_path = '/')
		name = 'unknown'
		version = 'unknown'
		redhat_release = "#{root_path}/etc/redhat-release"
		gentoo_release = "#{root_path}/etc/gentoo-release"
		lsb_release = "#{root_path}/etc/lsb-release"
		lsb_release_cmd = IO.popen('which lsb_release', 'r').gets.chomp
		if 0 < lsb_release_cmd.size
			name = IO.popen("#{lsb_release_cmd} -i", 'r').gets.chomp.split(/\t/)[1]
			version = IO.popen("#{lsb_release_cmd} -r", 'r').gets.chomp.split(/\t/)[1]
		elsif File.exist?(lsb_release)
			name = version = ''
			File.open(lsb_release, 'r').read.each_line do |line|
				case line.chomp
				when /^DISTRIB_ID=(.*)/
					name = $1.downcase
				when /^DISTRIB_RELEASE=([0-9.]*)/
					version = $1
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

	def network_restart_rhel(version, params, metadata)
		result = ''
		if params.include?(:debug)
			result = '/etc/init.d/network restart'
		else
			result = IO.popen('/etc/init.d/network restart', 'r').gets.chomp
		end
		return result
	end

	def network_restart_centos(version, params, metadata)
		return network_restart_rhel(version, params, metadata)
	end

	def set_networks_rhel(version, params, metadata)
		mac_addresses = []
		dns = []
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			mac_addresses << m['mac_address']
			m['dns'].each do |key, value|
				dns << value
			end
		end
		mac_addresses.sort!
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			if mac_addresses[0] == m['mac_address'] and m['gateway']
				gateway = %Q(GATEWAY="#{m['gateway']}")
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

	def set_networks_centos(version, params, metadata)
		return set_networks_rhel(version, params, metadata)
	end

	def set_networks_ubuntu(version, params, metadata)
		mac_addresses = []
		dns = []
		agent_config = @@dodai_instance_agent_config.load_config
		config = <<-EOL
auto lo
iface lo inet loopback
		EOL
		agent_config['interfaces'].each do |interface|
			if 'system' == interface['role']
				config += <<-EOL

auto #{interface['name']}
iface #{interface['name']} inet static
	address #{interface['ip_addresses'][0]}
	netmask #{interface['netmasks'][0]}
			EOL
			end
		end
		config += <<-EOL

		EOL
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			mac_addresses << m['mac_address']
			m['dns'].each do |key, value|
				dns << value
			end
		end
		mac_addresses.sort!
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			device_name = mac_to_nic(m['mac_address'])
			if mac_addresses[0] == m['mac_address'] and m['gateway']
				gateway = "gateway #{m['gateway']}"
			else
				gateway = ''
			end
			config += <<-EOL

auto #{device_name}
iface #{device_name} inet static
	address #{m['ip_address']}
	netmask #{m['netmask']}
	#{gateway}
			EOL
		end
		file_name = '/etc/network/interfaces'
		if params.include?(:debug)
			file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
		end
		File.open(file_name, 'w') do |file|
			file.puts config
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
			dns.each do |address|
				file.puts "nameserver #{address}"
			end
		end
		return true
	end

	def network_restart_ubuntu(version, params, metadata)
		result = ''
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			nic = mac_to_nic(m['mac_address'])
			if params.include?(:debug)
				result += "ifdown #{nic}\n"
			else
				result += IO.popen("ifdown #{nic}", 'r').gets.chomp
			end
		end
		metadata.each do |k, m|
			next unless k.include?(%r|^floating_ip_[0-9]*|)
			nic = mac_to_nic(m['mac_address'])
			if params.include?(:debug)
				result += "ifup #{nic}\n"
			else
				result += IO.popen("ifup #{nic}", 'r').gets.chomp
			end
		end
		return result
	end

	def set_networks(params)
		distro = get_distro_info
		openstack_metadata = get_openstack_metadata(
			params[:auth_token],
			params[:instance_id],
			params[:metadata_server],
			params[:tenant_id]
		)
		eval("set_networks_#{distro[:name]}(#{distro[:version]}, params, openstack_metadata)")
		eval("network_restart_#{distro[:name]}(#{distro[:version]}, params, openstack_metadata)")
		return true
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
				if 'system' == interface['role'] and mac == interface['mac_address']
					udev_system << [mac, "eth#{nic_number}"]
					@config['interfaces'][config_index]['name'] = "eth#{nic_number}"
					config_index += 1
					nic_number += 1
				elsif mac == interface['mac_address']
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
		public_key = ''
		if params.include?('public_key')
			public_key = params['public_key']
		else
			metadata = get_ec2_metadata
			public_key = metadata["/public-keys/0/openssh-key"]
		end
		file_name = '/root/.ssh/authorized_keys'
		action = ''
		cmdline = File.open('/proc/cmdline', 'r').read
		root_fs_type = ''
		if /.* root_fs_type=(.*) .*/ =~ cmdline
			root_fs_type = "-t #{$1}"
		end
		case cmdline
		when /.* action=deploy .*/
			action = :deploy
			result = IO.popen("mount #{root_fs_type} /dev/sda2 /mnt/sda2", 'r').gets
			file_name = '/mnt/sda2' + file_name
		end
		if params.include?(:debug)
			file_name = [@@dodai_env[:root], file_name.gsub('/', '.')].join('/')
		end
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

	get "#{resource_path}/variables.json" do
		content_type :json
		result = @@dodai_instance_agent_config.get_variables
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get "#{resource_path}/config.json" do
		content_type :json
		result = @@dodai_instance_agent_config.load_config
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get "#{resources[:state]}.json" do
		content_type :json
		result = get_state
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	get "#{resources[:power]}.json" do
		content_type :json
		result = get_power
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put "#{resources[:power]}.json" do
		content_type :json
		result = set_power(params)
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put "#{resources[:key]}.json" do
		content_type :json
		result = set_keypairs(params)
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

	put "#{resources[:networks]}.json" do
		content_type :json
		result = set_networks(params)
		if result
			{:result => result}.to_json
		else
			{:result => nil, :error => @@err_msg[:e500]}.to_json
		end
	end

end

config = DodaiInstanceAgentConfig.new.load_config
bind_address = DodaiInstanceAgentConfig.new.get_system_ip(config)
DodaiInstanceAgent.run! :bind => bind_address, :port => config['bind_port'].to_s

#vim: tabstop=3 shiftwidth=3 softtabstop=3
