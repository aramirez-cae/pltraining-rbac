require 'puppet/provider/rbac_api'

Puppet::Type.type(:rbac_role).provide(:ruby, :parent => Puppet::Provider::Rbac_api) do
  desc 'RBAC API provider for the rbac_role type'

  mk_resource_methods

  def self.instances
    $users = users
    $groups = groups
    Puppet::Provider::Rbac_api::get_response('/roles').collect do |role|
      Puppet.debug "RBAC: Inspecting role #{role.inspect}"
      # Turn ids into names
      user_names = role['user_ids'].map { |id| $users[id] }
      group_names = role['group_ids'].map { |id| $groups[id] }
      new(:ensure       => role['is_revoked'] ? :absent : :present,
          :id           => role['id'],
          :name         => role['display_name'],
          :description  => role['description'],
          :permissions  => role['permissions'],
          :users        => user_names,
          :groups       => group_names,
      )
    end
  end

  def self.prefetch(resources)
    vars = instances
    resources.each do |name, res|
      if provider = vars.find{ |v| v.name == res.name }
        res.provider = provider
      end
    end
  end

  def self.users
    users = {}
    Puppet::Provider::Rbac_api::get_response('/users').collect do |user|
      users[user['id']] = user['display_name']
    end
    users
  end

  def self.groups
    groups = {}
    Puppet::Provider::Rbac_api::get_response('/groups').collect do |group|
      groups[group['id']] = group['login']
    end
    groups
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  def create
    Puppet.debug "RBAC: Creating new role #{resource[:name]}"

    [ :name, :description ].each do |prop|
      raise ArgumentError, 'description, and name are required attributes' unless resource[prop]
    end

    # Transform names into ids
    user_ids = resource['user_ids'].map { |name| $users.key(name) }
    group_ids = resource['group_ids'].map { |name| $groups.key(name) }

    role = {
      'description'  => resource[:description],
      'display_name' => resource[:name],
      'permissions'  => resource[:permissions],
      'user_ids'     => user_ids,
      'group_ids'    => group_ids,
    }
    Puppet::Provider::Rbac_api::post_response('/roles', role)

    @property_hash[:ensure] = :present
  end

  def destroy
    Puppet::Provider::Rbac_api::delete_response("/roles/#{@property_hash[:id]}")
    @property_hash[:ensure] = :absent
  end

  define_method "name=" do |value|
    fail "The name parameter cannot be changed after creation."
  end

  define_method "id=" do |value|
    fail "The id parameter is read-only."
  end

  def flush
    # so, flush gets called, even on create() and delete()
    return if @property_hash[:id].nil?
    return if @property_hash[:ensure] == :absent

    # Turn names into ids
    user_ids = @property_hash[:users].map { |name| $users.key(name) }
    group_ids = @property_hash[:groups].map { |name| $groups.key(name) }

    role = {
      'id'           => @property_hash[:id],
      'description'  => @property_hash[:description],
      'display_name' => @property_hash[:name],
      'permissions'  => @property_hash[:permissions],
      'user_ids'     => user_ids,
      'group_ids'    => group_ids,
    }

    Puppet.debug "RBAC: Updating role #{role.inspect}"
    Puppet::Provider::Rbac_api::put_response("/roles/#{@property_hash[:id]}", role)
  end

  def revoked?
    @property_hash[:ensure] == :absent
  end

end
