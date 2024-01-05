class ::Proxy::PluginNotFound < ::StandardError; end
class ::Proxy::PluginVersionMismatch < ::StandardError; end
class ::Proxy::PluginMisconfigured < ::StandardError; end
class ::Proxy::PluginProviderNotFound < ::StandardError; end
class ::Proxy::PluginLoadingAborted < ::StandardError; end

class ::Proxy::Plugins
  include ::Proxy::Log

  # 如果 @instance 实例变量还没有被赋值，那么创建一个新的 Proxy::Plugins 实例，并将其赋值给 @instance。
  # 在之后的调用中，self.instance 方法将直接返回已存在的 @instance 实例，而不会重复创建新的实例。
  # @instance 是這個類本身的實例變量,是依附在這個類本身的,不是依附在類實例上。
  def self.instance
    @instance ||= ::Proxy::Plugins.new
  end

  def plugin_loaded(a_name, a_version, a_class)
    self.loaded += [{:name => a_name, :version => a_version, :class => a_class, :state => :uninitialized}]
  end

  # ===== loaded 的返回值是一組 hash [{ :name => :xxx, :version => :xxx, ... }, { :name => :xxx, :version => :xxx ...}, ... ] =====
  # 所有安裝的 plugin 插件,都會被填入這個 loaded 數組中。
  #
  # each element of the list is a hash containing:
  #
  # :name: module name
  # :version: module version
  # :class: module class
  # :state: :uninitialized, :loaded, :staring, :running, :disabled, or :failed
  # :di_container: dependency injection container used by the module
  # :http_enabled: true or false (not used by providers)
  # :https_enabled: true or false (not used by providers)
  #================================================================================================================================
  def loaded
    @loaded ||= []
  end

  attr_writer :loaded

  # 從 loaded 陣列中刪除同名的舊插件，並將已更新的插件添加到 loaded 陣列中，從而更新插件。
  def update(updated_plugins)
    updated_plugins.each do |updated|
      loaded.delete_if { |p| p[:name] == updated[:name] }
      loaded << updated
    end
  end
  '''
  上面的方法,也可以用以下的做法
  def update(updated_plugins)
    # result = some_hash.slice(key1, key2, key3, ...); 將 key1, key2, key3 ... 这些键对应的值将被提取出来，形成一个新的哈希表（字典）。
    # 傳參 *loaded.keys是将字典 loaded 的所有键作为参数传递给slice()函数。这将返回一个包含所有键的切片对象，可以用于对其他序列进行切片操作。
    loaded.merge(updated_plugins).slice(*loaded.keys)
  end
  '''
  # 迭代 loaded 數組,將 loaded 數組中的每個元素傳遞給塊,以塊做為過濾條件,返回第一個符合條件的元素。
  def find
    loaded.find do |plugin|  # 此行的 find 是数组的一个迭代方法，它接受一个块（block）作为参数。
      # 塊（block）中的程式碼用於檢查 plugin 數組中的元素是否滿足條件。
      # 如果塊返回一個真值（true 或非 nil），則 find 方法會停止迭代並返回該元素 plugin。(即為第一個符合條件的元素)
      yield plugin  
    end
  end

  # 迭代 loaded 數組,將 loaded 數組中的每個元素傳遞給塊,以塊做為過濾條件返回一個新數組。
  def select
    loaded.select do |plugin|   # 将根据块中的条件筛选出满足条件的插件，并返回一个新的数组。
      yield plugin
    end
  end
  


  # ***** below are methods that are going to be removed/deprecated ***** 

  def enabled_plugins
    loaded.select { |p| p[:state] == :running && p[:class].ancestors.include?(::Proxy::Plugin) }.map { |p| p[:class] }
  end

  def plugin_enabled?(plugin_name)
    plugin = loaded.find { |p| p[:name] == plugin_name.to_sym }
    plugin.nil? ? false : plugin[:state] == :running
  end

  def find_plugin(plugin_name)
    p = loaded.find { |plugin| plugin[:name] == plugin_name.to_sym }
    return p[:class] if p
  end

  def find_provider(provider_name)
    provider = loaded.find { |p| p[:name] == provider_name.to_sym }
    raise ::Proxy::PluginProviderNotFound, "Provider '#{provider_name}' could not be found" if provider.nil? || !provider[:class].ancestors.include?(::Proxy::Provider)
    provider[:class]
  end
end
