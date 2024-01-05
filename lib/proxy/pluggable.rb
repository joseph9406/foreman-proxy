require 'ostruct'
module Proxy::Pluggable
  attr_reader :plugin_name, :version, :after_activation_blk

  # Methods below define DSL for defining plugins
  def after_activation(&blk)
    @after_activation_blk = blk
  end

  def requires(plugin_name, version_spec)
    dependencies << ::Proxy::Dependency.new(plugin_name, cleanup_version(version_spec))
  end

  def bundler_group(name)
    @bundler_group_name = name
  end

  def capability(capability)
    capabilities << capability
  end

  # relative to ::Proxy::SETTINGS.settings_directory
  def settings_file(apath = nil)  # 如果 apath 为空，表示调用 settings_file 方法时没有传入任何参数。
    if apath.nil?
      @settings_file || "#{plugin_name}.yml"
    else
      @settings = nil
      @settings_file = apath
    end
  end

  def default_settings(a_hash = {})
    @plugin_default_settings ||= {}
    @plugin_default_settings.merge!(a_hash)
  end

  def expose_setting(setting)
    exposed_settings << setting
  end

  def initialize_after(*module_names)
    raise "#{plugin_name}: 'initialize_after' method has been removed."
  end

  def validate_readable(*settings)
    validate(*settings.push(:file_readable => true))
  end

  def validate_presence(*settings)
    validate(*settings.push(:presence => true))
  end

  def validate(*settings)
    validator_params = settings.pop
    predicate = validator_params.delete(:if)
    validator_name = validator_params.keys.first
    validator_args = validator_params[validator_name]

    settings.each { |setting| validations << {:name => validator_name, :predicate => predicate, :args => validator_args, :setting => setting} }
  end

  def override_module_loader_class(a_class_or_a_class_name)
    @module_loader_class = case a_class_or_a_class_name
                           when String
                             eval(a_class_or_a_class_name)
                           else
                             a_class_or_a_class_name
                           end
  end

  def load_validators(hash_of_validators)
    @custom_validators = hash_of_validators
  end

  def load_dependency_injection_wirings(class_name_to_use = nil, &block_to_use)
    @di_wirings_loader = class_name_to_use || block_to_use
  end

  def load_programmable_settings(class_name_to_use = nil, &block_to_use)
    @programmable_settings = class_name_to_use || block_to_use
  end

  def load_classes(class_name_to_use = nil, &block_to_use)
    @class_loader = class_name_to_use || block_to_use
  end

  def start_services(*di_labels)
    @services = di_labels
  end

  #
  # End of DSL
  #

  attr_writer :settings
  def settings
    @settings ||= OpenStruct.new
  end

  def module_loader_class
    # 如果 @module_loader_class 原本己被赋值，就返回原值,
    # 若沒有賦值,就以 "||=" 右邊的值賦值給 @settings_file,
    # 检查 after_activation_blk 是否为空。如果为空，则将 @settings_file 赋值为 ::Proxy::DefaultModuleLoader 类的名称，否则赋值为 ::Proxy::LegacyModuleLoader 类的名称。   
    @module_loader_class ||= after_activation_blk.nil? ? ::Proxy::DefaultModuleLoader : ::Proxy::LegacyModuleLoader
  end

  class ClassLoaderProcWrapper
    def initialize(a_blk)
      @a_blk = a_blk
    end

    def load_classes
      @a_blk.call
    end
  end
  
  def class_loader
    return nil if @class_loader.nil?
    case @class_loader
    when String
      eval(@class_loader).new
    when Proc
      ClassLoaderProcWrapper.new(@class_loader)
    else
      @class_loader.new
    end
  end

  class SettingsProcWrapper
    def initialize(a_blk)
      @a_blk = a_blk
    end

    def load_programmable_settings(settings)
      @a_blk.call(settings)
    end
  end
  
  def programmable_settings
    return nil if @programmable_settings.nil?
    case @programmable_settings
    when String
      eval(@programmable_settings).new
    when Proc
      SettingsProcWrapper.new(@programmable_settings)
    else
      @programmable_settings.new
    end
  end

  class DiWiringsProcWrapper
    def initialize(a_blk)
      @a_blk = a_blk
    end

    def load_dependency_injection_wirings(container, settings)
      @a_blk.call(container, settings)
    end
  end
  
  def di_wirings
    return nil if @di_wirings_loader.nil?
    case @di_wirings_loader
      when String
        eval(@di_wirings_loader).new
      when Proc
        DiWiringsProcWrapper.new(@di_wirings_loader)
      else
        @di_wirings_loader.new
    end
  end

  def custom_validators
    @custom_validators || {}
  end

  def services
    @services ||= []
  end

  def loading_failed(message)
    raise ::Proxy::PluginLoadingAborted, message
  end

  def capabilities
    @capabilities ||= []
  end

  def dependencies
    @dependencies ||= []
  end

  def exposed_settings
    @exposed_settings ||= []
  end

  def bundler_group_name
    @bundler_group_name || plugin_name
  end

  def plugin_default_settings
    @plugin_default_settings ||= {}
  end

  def validations
    @validations ||= []
  end

  def cleanup_version(version)
    version.chomp('-develop').sub(/\-RC\d+$/i, '')
  end
end
