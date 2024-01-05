module ::Proxy::Settings
  class Global < ::OpenStruct
    DEFAULT_SETTINGS = {
      :settings_directory => Pathname.new(__dir__).join("..", "..", "..", "config", "settings.d").expand_path.to_s,
      :https_port => 8443,
      :log_file => "/var/log/proxy/proxy.log",
      :file_rolling_keep => 6,  # 表示要保留的日志文件数量。
      :file_rolling_size => 0,
      :file_rolling_age => 'weekly',
      # %d：这是日期和时间的占位符，表示记录日志消息的时间戳。
      # %.8X{request}：这部分包含了一个自定义的占位符 %X{request}，它表示要记录的日志消息中的一个字段或属性，
      #   该字段的名称是 request。%.8 是一个格式化选项，表示要显示 request 字段的前 8 个字符。
      #   具体的字段值将在日志记录时从日志事件中提取并替换。
      # [%.1l]：这是日志级别的占位符，表示记录日志消息的日志级别。%.1l 使用了格式化选项，将日志级别限制为一位字符（例如，E 表示 ERROR）。日志级别将被替换为实际的日志级别值。
      # %m：这是消息文本的占位符，表示要记录的日志消息文本。%m 将被替换为实际的日志消息文本。
      # %c：日志器的名字。
      # %C：日志器的全名（包括命名空间）。
      :file_logging_pattern => '%d %.8X{request} [%.1l] %m',
      :system_logging_pattern => '%m',
      :log_level => "INFO",
      :daemon => false,
      :daemon_pid => "/var/run/foreman-proxy/foreman-proxy.pid",
      :forward_verify => true,
      :bind_host => ["*"],
      :log_buffer => 2000,
      :log_buffer_errors => 1000,
      :ssl_disabled_ciphers => [],
      :tls_disabled_versions => [],
      :dns_resolv_timeouts => [5, 8, 13], # Ruby default is [5, 20, 40] which is a bit too much for us
    }

    HOW_TO_NORMALIZE = {
      :foreman_url => ->(value) { value.end_with?("/") ? value : value + "/" },
      :bind_host => ->(value) { value.is_a?(Array) ? value : [value] },
    }

    attr_reader :used_defaults

    def initialize(settings)
      if RUBY_PLATFORM =~ /mingw/
        settings.delete :puppetca if settings.has_key? :puppetca
        settings.delete :puppet   if settings.has_key? :puppet
        settings[:x86_64] = File.exist?('c:\windows\sysnative\cmd.exe')
      end

      @used_defaults = DEFAULT_SETTINGS.keys - settings.keys

      default_and_user_settings = DEFAULT_SETTINGS.merge(settings)
      # Hash[...],用来将数组转换为哈希表。[[k1,v1],[k2,v2],[k3,v4],...] 轉成 {k1 => v1, k2 => v2, k3 => v3, ...}
      settings_to_use = Hash[ default_and_user_settings.map do |key, value|
        [key, normalize_setting(key, value, HOW_TO_NORMALIZE)]
      end ]

      super(settings_to_use)
    end

    def normalize_setting(key, value, how_to)
      return value unless how_to.has_key?(key)
      how_to[key].call(value)
    end

    def apply_argv(args)
      self.daemon = true if args.include?('--daemonize')
      self.daemon = false if args.include?('--no-daemonize')
    end
  end
end
