require 'proxy/default_di_wirings'
require 'proxy/default_plugin_validators'

class ::Proxy::PluginGroup
  include ::Proxy::Log
  attr_reader :plugin, :providers, :state, :di_container

  def initialize(a_plugin, providers = [], di_container = ::Proxy::DependencyInjection::Container.new)
    @plugin = a_plugin
    @state = :uninitialized # :uninitialized -> :starting -> :running, or :uninitialized -> :disabled, or :uninitialized -> :starting -> :failed
    @providers = providers
    @di_container = di_container
    @http_enabled = false
    @https_enabled = false
  end

  def inactive?
    @state == :failed || @state == :disabled
  end

  def http_enabled?
    @http_enabled
  end

  def https_enabled?
    @https_enabled
  end

  def capabilities
    members.map(&:capabilities).compact.flatten  # 展開後不會刪除重複的元素
  end

  def exposed_settings
    result = {}

    members.each do |member|
      member.exposed_settings.each do |setting|
        result[setting] = member.settings[setting]
      end
    end

    if @plugin.uses_provider?
      result[:use_provider] = @plugin.settings['use_provider']
    end

    result
  end

  def resolve_providers(all_plugins_and_providers)
    return if inactive?
    return unless @plugin.uses_provider?

    used_providers = [@plugin.settings.use_provider].flatten.map(&:to_sym)  
    providers = all_plugins_and_providers.select { |p| used_providers.include?(p[:name].to_sym) }

    not_available = used_providers - providers.map { |p| p[:name].to_sym }

    if not_available.empty?
      logger.debug "Providers #{printable_module_names(used_providers)} are going to be configured for '#{@plugin.plugin_name}'"
      return @providers = providers.map { |p| p[:class] }
    end

    fail_group_with_message("Disabling all modules in the group #{printable_module_names(member_names)}: following providers are not available #{printable_module_names(not_available)}")
  end

  def members
    providers + [plugin]   # ['aaa','bbb'] + ['ccc','ddd'] 變成 ["aaa", "bbb", "ccc", "ddd"] 
  end

  def member_names
    members.map(&:plugin_name)
  end

  def printable_module_names(names)
    printable = names.map { |name| "'#{name}'" }.join(", ")
    "[#{printable}]"
  end

  def load_plugin_settings
    settings = plugin.module_loader_class.new(plugin, di_container).load_plugin_settings
    update_group_initial_state(settings[:enabled])
  rescue Exception => e
    fail_group(e)
  end

  def update_group_initial_state(enabled_setting)
    @http_enabled = ::Proxy::Settings::Plugin.http_enabled?(enabled_setting)
    @https_enabled = ::Proxy::Settings::Plugin.https_enabled?(enabled_setting)
    @state = (http_enabled? || https_enabled?) ? :starting : :disabled
  end

  def set_group_state_to_failed
    @http_enabled = false
    @https_enabled = false
    @state =  :failed
  end

  def load_provider_settings
    return if inactive?
    providers.each do |p|
      p.module_loader_class.new(p, di_container).load_provider_settings(plugin.settings.marshal_dump)
    end
  rescue Exception => e
    fail_group(e)
  end

  def configure
    return if inactive?
    members.each { |p| p.module_loader_class.new(p, di_container).configure_plugin }
    @state = :running
  rescue Exception => e
    stop_services
    fail_group(e)
  end

  def fail_group(an_exception)
    fail_group_with_message("Disabling all modules in the group #{printable_module_names(member_names)} due to a failure in one of them: #{an_exception}", an_exception.backtrace)
  end

  def fail_group_with_message(a_message, an_exception = nil)
    set_group_state_to_failed
    logger.error(a_message, an_exception)
    members.each do |m|
      ::Proxy::LogBuffer::Buffer.instance.failed_module(m.plugin_name, a_message)
    end
  end

  def stop_services
    members.each do |member|
      member.services.map { |label| di_container.get_dependency(label) }.each { |service| service.stop if service.respond_to?(:stop) }
    end
  end

  def validate_dependencies_or_fail(enabled_providers_and_plugins)
    members.each { |p| validate_dependencies!(p, p.dependencies, enabled_providers_and_plugins) }
  rescue Exception => e
    stop_services
    fail_group(e)
  end

  def validate_dependencies!(plugin, dependencies, enabled_providers_and_plugins)
    dependencies.each do |dep|
      found = enabled_providers_and_plugins[dep.name]
      raise ::Proxy::PluginNotFound, "'#{dep.name}' required by '#{plugin.plugin_name}' could not be found." unless found
      unless ::Gem::Dependency.new('', dep.version).match?('', found.cleanup_version(found.version))
        raise ::Proxy::PluginVersionMismatch, "Available version '#{found.version}' of '#{dep.name}' doesn't match version '#{dep.version}' required by '#{plugin.plugin_name}'"
      end
    end
  end
end

class ::Proxy::PluginInitializer
  attr_accessor :plugins

  def initialize(plugins)
    @plugins = plugins
  end

  def initialize_plugins
    loaded_plugins = plugins.loaded.select { |plugin| plugin[:class].ancestors.include?(::Proxy::Plugin) }
    grouped_with_providers = loaded_plugins.map { |p| ::Proxy::PluginGroup.new(p[:class], [], Proxy::DependencyInjection::Container.new) }
    plugins.update(current_state_of_modules(plugins.loaded, grouped_with_providers))

    # load main plugin settings, as this may affect which providers will be selected
    grouped_with_providers.each(&:load_plugin_settings) # 每次遍歷數組中的一個對象，都會調用該對象的 load_plugin_settings 方法;等同於 each { |e| e.load_plugin_settings }。
    plugins.update(current_state_of_modules(plugins.loaded, grouped_with_providers))

    # resolve provider names to classes
    grouped_with_providers.each { |group| group.resolve_providers(plugins.loaded) }
    # validate prerequisite versions and availability
    all_enabled = all_enabled_plugins_and_providers(grouped_with_providers)
    grouped_with_providers.each do |group|
      next if group.inactive?
      group.validate_dependencies_or_fail(all_enabled)
    end
    # load provider plugin settings
    grouped_with_providers.each(&:load_provider_settings)
    plugins.update(current_state_of_modules(plugins.loaded, grouped_with_providers))

    # configure each plugin & providers
    grouped_with_providers.each(&:configure)

    # validate prerequisites again, as some may have been disabled during loading
    all_enabled = all_enabled_plugins_and_providers(grouped_with_providers) 
    grouped_with_providers.each do |group|
      next if group.inactive?
      group.validate_dependencies_or_fail(all_enabled)
    end

    plugins.update(current_state_of_modules(plugins.loaded, grouped_with_providers))
  end

  def current_state_of_modules(all_plugins, all_groups)
    to_update = all_plugins.dup  # dup 是一個方法，用於創建對象的淺拷貝（shallow copy）。它返回一個新的對象，其中包含原始對象的所有實例變量的值。

    # 注意!! 通过修改 updated 的值，就相当于更新了 to_update 的值(因為 hash 和 數組 都是可變對象)。
    # 因為 hash 和 數組 都是可變對象, updated 和 to_update 都是指向同一个对象，所以在修改updated的同时，to_update也会被修改。
    all_groups.each do |group|
      # note that providers do not use http_enabled and https_enabled
      updated = to_update.find { |loaded_plugin| loaded_plugin[:name] == group.plugin.plugin_name } # find 方法只會返回第一個符合條件的元素。(找到後就直接返回了,不會再往下找了)
      updated[:di_container] = group.di_container
      updated[:state] = group.state
      updated[:http_enabled] = group.http_enabled?
      updated[:https_enabled] = group.https_enabled?
      updated[:capabilities] = group.capabilities
      updated[:settings] = group.exposed_settings
      group.providers.each do |group_member|
        updated = to_update.find { |loaded_plugin| loaded_plugin[:name] == group_member.plugin_name }
        updated[:di_container] = group.di_container
        updated[:state] = group.state
      end
    end    
    to_update
  end

  def all_enabled_plugins_and_providers(all_groups)
    # each_with_object 返回的是累积对象本身。result = [1, 2, 3].each_with_object([]) { |num, array| array << num * 2 }; 返回 [2, 4, 6]
    # inject 返回的是最后一次块执行后的结果。 result = [1, 2, 3].inject(0) { |sum, num| sum + num }; 返回 6
    all_groups.each_with_object({}) do |group, all|  
      group.members.each { |p| all[p.plugin_name] = p } unless group.inactive?
    end
  end
end

module ::Proxy::LegacyRuntimeConfigurationLoader
  def configure_plugin
    plugin.class_eval(&plugin.after_activation_blk)
    logger.info("Successfully initialized '#{plugin.plugin_name}'")
  rescue Exception => e
    logger.error "Couldn't enable '#{plugin.plugin_name}'", e
    ::Proxy::LogBuffer::Buffer.instance.failed_module(plugin.plugin_name, e.message)
  end
end

module ::Proxy::DefaultRuntimeConfigurationLoader
  def configure_plugin
    wire_up_dependencies(plugin.di_wirings, plugin.settings.marshal_dump, di_container)
    start_services(plugin.services, di_container)
    logger.info("Successfully initialized '#{plugin.plugin_name}'")
  rescue Exception => e
    logger.error "Couldn't enable '#{plugin.plugin_name}'", e
    ::Proxy::LogBuffer::Buffer.instance.failed_module(plugin.plugin_name, e.message)
    raise e
  end

  def wire_up_dependencies(di_wirings, config, container)
    [::Proxy::DefaultDIWirings, di_wirings].compact.each do |wiring|
      wiring.load_dependency_injection_wirings(container, config)
    end
  end

  def start_services(services, container)
    services.each do |s|
      instance = container.get_dependency(s)
      instance.start if instance.respond_to?(:start)
    end
  end
end

module ::Proxy::DefaultSettingsLoader
  def load_plugin_settings
    puts "*** module ::Proxy::DefaultSettingsLoader ***"
    load_settings({}) { |s| log_used_settings(s) }
  end

  def load_provider_settings(main_plugin_settings)
    load_settings(main_plugin_settings) { |s| log_provider_settings(s) }
  end

  def load_settings(main_plugin_settings)
    config_file_settings = load_configuration_file(plugin.settings_file)

    merged_with_defaults = plugin.default_settings.merge(config_file_settings)

    return merged_with_defaults unless module_enabled?(merged_with_defaults)  # 当模块被禁用时，直接返回默认的配置merged_with_defaults，而不再执行后续的代码。

    # load dependencies before loading custom settings and running validators -- they may need those classes
    ::Proxy::BundlerHelper.require_groups(:default, plugin.bundler_group_name)
    load_classes

    config_merged_with_main = merge_settings(merged_with_defaults, main_plugin_settings)
    settings = load_programmable_settings(config_merged_with_main)

    plugin.settings = ::Proxy::Settings::Plugin.new({}, settings)

    yield settings

    validate_settings(plugin, settings)

    settings
  end

  def module_enabled?(user_settings)
    return true if plugin.ancestors.include?(::Proxy::Provider)
    !!user_settings[:enabled]  # !操作符将一个值转换为其相反的布尔值。而!!则是两次逻辑非操作，即将一个值的布尔值再次取反，从而将其转换为其原始的布尔值。
  end

  def load_configuration_file(settings_file)
    begin
      settings = Proxy::Settings.read_settings_file(settings_file)
    rescue Errno::ENOENT
      logger.warn("Couldn't find settings file #{::Proxy::SETTINGS.settings_directory}/#{settings_file}. Using default settings.")
      settings = {}
    end
    settings
  end

  def merge_settings(provider_settings, main_plugin_settings)
    main_plugin_settings.delete(:enabled)
    # all modules have 'enabled' setting, we ignore it when looking for duplicate setting names
    unless (overlap = main_plugin_settings.keys - (main_plugin_settings.keys - provider_settings.keys)).empty?  # 這不就是交集嗎? 因為ruby中沒有方法可以取得兩個 hash 集合的交集
      raise Exception, "Provider '#{plugin.plugin_name}' settings conflict with the main plugin's settings: #{overlap}"
    end
    provider_settings.merge(main_plugin_settings)
  end

  def log_used_settings(settings)
    log_provider_settings(settings)
    logger.debug("'%s' ports: 'http': %s, 'https': %s" % [plugin.plugin_name,
                                                          ::Proxy::Settings::Plugin.http_enabled?(settings[:enabled]),
                                                          ::Proxy::Settings::Plugin.https_enabled?(settings[:enabled])])
  end

  def log_provider_settings(settings)
    default_settings = plugin.plugin_default_settings
    sorted_keys = settings.keys.sort
    to_log = sorted_keys.map { |k| "'%s': %s%s" % [k, settings[k], (default_settings.include?(k) && default_settings[k] == settings[k]) ? " (default)" : ""] }.join(", ")
    logger.debug "'%s' settings: %s" % [plugin.plugin_name, to_log]
  end

  def load_programmable_settings(settings)
    plugin.programmable_settings&.load_programmable_settings(settings)
    settings
  end

  def load_classes
    # 如果 plugin.class_loader 不为 nil，则会调用 load_classes 方法；如果 plugin.class_loader 为 nil，则表达式会返回 nil，而不会产生错误。
    plugin.class_loader&.load_classes
  end

  def validate_settings(plugin, config)
    result = execute_validators(plugin.plugin_default_settings.keys.map { |k| {:name => :presence, :setting => k} }, config)
    result + execute_validators(plugin.validations, config)
  end

  def execute_validators(validations, config)
    available_validators = Proxy::DefaultPluginValidators.validators.merge(plugin.custom_validators)

    validations.inject([]) do |all, validator|
      validator_class = available_validators[validator[:name]]
      raise Exception, "Encountered an unknown validator '#{validator[:name]}' when validating '#{plugin.plugin_name}' module." if validator_class.nil?
      validator_class.new(plugin, validator[:setting], validator[:args], validator[:predicate]).evaluate_predicate_and_validate!(config)
      all << {:class => validator_class, :setting => validator[:setting], :args => validator[:args], :predicate => validator[:predicate]}
    end
  end
end

class ::Proxy::DefaultModuleLoader
  include ::Proxy::Log
  include ::Proxy::DefaultSettingsLoader
  include ::Proxy::DefaultRuntimeConfigurationLoader

  attr_reader :plugin, :di_container

  def initialize(a_plugin, di_container)
    @di_container = di_container
    @plugin = a_plugin
  end
end

class ::Proxy::LegacyModuleLoader
  include ::Proxy::Log
  include ::Proxy::DefaultSettingsLoader
  include ::Proxy::LegacyRuntimeConfigurationLoader

  attr_reader :plugin, :di_container

  def initialize(a_plugin, di_container)
    @di_container = di_container
    @plugin = a_plugin
  end
end
