require "yaml"
require "ostruct"
require "pathname"

module Proxy::Settings
  extend ::Proxy::Log

  SETTINGS_PATH = Pathname.new(__dir__).join("..", "..", "config", "settings.yml")  # "__dir__" 指向包含當前腳本文件的目錄的字符串

  def self.initialize_global_settings(settings_path = nil, argv = ARGV)
    global = ::Proxy::Settings::Global.new(YAML.load(File.read(settings_path || SETTINGS_PATH))) # YAML.load 用于将YAML格式的字符串转换为Ruby对象(即 hash)
    global.apply_argv(argv)
    global
  end

  def self.load_plugin_settings(defaults, settings_file, settings_directory = nil)
    settings = {}
    begin
      settings = YAML.load(File.read(File.join(settings_directory || ::Proxy::SETTINGS.settings_directory, settings_file))) || {}
    rescue Errno::ENOENT
      logger.warn("Couldn't find settings file #{settings_directory || ::Proxy::SETTINGS.settings_directory}/#{settings_file}. Using default settings.")
    end
    ::Proxy::Settings::Plugin.new(defaults, settings)
  end

  def self.read_settings_file(settings_file, settings_directory = nil)
    YAML.load(File.read(File.join(settings_directory || ::Proxy::SETTINGS.settings_directory, settings_file))) || {}
  end
end
