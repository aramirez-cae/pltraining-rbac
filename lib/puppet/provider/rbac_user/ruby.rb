require 'puppet/provider/rbac_api'

Puppet::Type.type(:rbac_user).provide(:ruby, :parent => Puppet::Provider::Rbac_api) do
  desc 'RBAC API provider for the rbac_user type'

  mk_resource_methods

  def self.instances
    $roles = roles
    Puppet::Provider::Rbac_api::get_response('/users').collect do |user|
      Puppet.debug "RBAC: Inspecting user #{user.inspect}"
      # Turn ids into names
      role_names = user['role_ids'].map { |id| $roles[id] }
      new(:ensure       => user['is_revoked'] ? :absent : :present,
          :id           => user['id'],
          :name         => user['login'],
          :display_name => user['display_name'],
          :email        => user['email'],
          :roles        => role_names,
          :remote       => user['is_remote'],
          :superuser    => user['is_superuser'],
          :last_login   => user['last_login'],
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

  def self.roles
    roles = {}
    Puppet::Provider::Rbac_api::get_response('/roles').collect do |role|
      roles[role['id']] = role['display_name']
    end
    roles
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  def create
    if @property_hash.empty?
      Puppet.debug "RBAC: Creating new user #{resource[:name]}"

      [ :display_name, :email ].each do |prop|
        raise ArgumentError, 'name, email, and display_name are required attributes' unless resource[prop]
      end

      # Transform role names into role ids
      role_ids = resource[:roles].map { |name| $roles.key(name) }

      user = {
        'login'        => resource[:name],
        'email'        => resource[:email],
        'display_name' => resource[:display_name],
        'role_ids'     => role_ids,
      }
      Puppet::Provider::Rbac_api::post_response('/users', user)

      if resource[:password]
        set_password(resource[:name], resource[:password])
      end
    else
      # if the user object exists, then it must have been disabled. Let's just re-enable it
      # and provide an opportunity to reset the password
      Puppet.debug "RBAC: Re-enabling user #{@property_hash.inspect}"

      if @property_hash.has_key? :password
        set_password(@property_hash[:id], @property_hash[:password])
      end
    end

    @property_hash[:ensure] = :present
  end

  def destroy
    # We cannot actually remove the user, so we'll revoke it instead
    @property_hash[:ensure] = :absent
  end

  [ :name, :display_name, :email ].each do |param|
    define_method "#{param}=" do |value|
      fail "The #{param} parameter cannot be changed after creation."
    end
  end

  [ :remote, :superuser, :last_login, :id ].each do |param|
    define_method "#{param}=" do |value|
      fail "The #{param} parameter is read-only."
    end
  end

  def password=(should)
    Puppet.debug 'RBAC: Ignoring password attribute as we do not have the ability to manage it'
  end

  def flush
    # so, flush gets called, even on create()
    return if @property_hash[:id].nil?

    # Turn role names into ids
    role_ids = @property_hash[:roles].map { |name| $roles.key(name) }

    user = {
      'is_revoked'   => revoked?,
      'id'           => @property_hash[:id],
      'login'        => @property_hash[:name],
      'email'        => @property_hash[:email],
      'display_name' => @property_hash[:display_name],
      'role_ids'     => role_ids,
      'is_remote'    => @property_hash[:remote],
      'is_superuser' => @property_hash[:superuser],
      'last_login'   => @property_hash[:last_login],
      'is_group'     => false,
    }

    Puppet.debug "RBAC: Updating user #{user.inspect}"
    Puppet::Provider::Rbac_api::put_response("/users/#{@property_hash[:id]}", user)
  end

  def revoked?
    @property_hash[:ensure] == :absent
  end

private

  def set_password(id, password)
    Puppet.debug "RBAC: Setting password for #{id}"

    if id.class == String
      begin
        users = Puppet::Provider::Rbac_api::get_response('/users')
        id    = users.select { |user| user['login'] == id }.first['id']
       rescue NoMethodError => e
        fail "User #{id} does not exist"
      end

      Puppet.debug "RBAC: Retrieved user id of #{id}"
    end

    token = Puppet::Provider::Rbac_api::post_response("/users/#{id}/password/reset", nil).body

    reset = {
      'token'    => token,
      'password' => password,
    }

    Puppet::Provider::Rbac_api::post_response("/auth/reset", reset)
  end

end
