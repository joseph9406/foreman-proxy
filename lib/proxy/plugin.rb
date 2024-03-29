require 'bundler_helper'

class ::Proxy::Dependency
  attr_reader :name, :version

  def initialize(aname, aversion)
    @name = aname.to_sym
    @version = aversion
  end
end

#
# example of plugin API
#
# class ExamplePlugin < ::Proxy::Plugin
#  plugin :example, "1.2.3"
#  config_file "example.yml"
#  http_rackup_path File.expand_path("http_config.ru", __dir__) # note no https rackup path, module will not be available over https
#  requires :foreman_proxy, ">= 1.5.develop"
#  requires :another_plugin, "~> 1.3.0"
#  default_settings :first => 'first', :second => 'second'
#
#  load_classes 'a/b', 'a/c', ...
#  load_validators 'Module::Class'
#  validate :setting1, :setting2, :blah_validator => {:param1 => 'val_one'}, :if => lambda {|settings| ...}
#  dependency_injection_wirings 'Module::Class' #expects load_bindings(container, settings)
#  start_services :binding_1, :binding_2, #expects 'start' method
#
#  after_activation { call_that }
#  bundler_group :blah
# end
#
class ::Proxy::Plugin
  extend ::Proxy::Pluggable
  extend ::Proxy::Log

  class << self
    attr_reader :get_http_rackup_path, :get_https_rackup_path, :get_uses_provider

    def rackup_path(path)
      http_rackup_path(path)
      https_rackup_path(path)
    end

    def http_rackup_path(path)
      @get_http_rackup_path = path
    end

    def https_rackup_path(path)
      @get_https_rackup_path = path
    end

    def plugin(plugin_name, aversion)
      @plugin_name = plugin_name.to_sym
      @version = aversion.chomp('-develop')  # 將末尾的 "-develop" 刪除，若不包含 "-develop",則返回原字串
      ::Proxy::Plugins.instance.plugin_loaded(@plugin_name, @version, self)
    end

    def uses_provider
      @get_uses_provider = true
    end

    # End of DSL
    def uses_provider?
      !!@get_uses_provider
    end

    def http_rackup
      #  File.read(get_http_rackup_path) 读取 get_http_rackup_path 所指定的文件内容,返回字符串。
      get_http_rackup_path ? File.read(get_http_rackup_path) : ""  
    end

    def https_rackup
      get_https_rackup_path ? File.read(get_https_rackup_path) : ""
    end
  end
end
