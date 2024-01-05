class ::Proxy::Provider
  extend ::Proxy::Pluggable  # extend 关键字用于向类添加模块中的方法，使成為該類的類方法

  class << self
    attr_reader :provider_factory

    def plugin(plugin_name, aversion, attrs = {})
      @plugin_name = plugin_name.to_sym
      @version = aversion.chomp('-develop')
      @provider_factory = attrs[:factory]
      ::Proxy::Plugins.instance.plugin_loaded(@plugin_name, @version, self)
    end
  end

  def provider_factory
    self.class.provider_factory  # self.class 返回當前對象所屬的類,
  end
end
