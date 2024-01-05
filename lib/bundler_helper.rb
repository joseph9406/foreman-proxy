#********************************* Gemfile.in 是什麼東西 *********************************************
# 而 Gemfile.in 则类似于标准的 Gemfile，但它可能是一个定制化的 Gemfile 文件，可能包含一些特殊的需求或配置。
# 这个文件的后缀名 .in 可能表示它是一个模板文件，它会在构建过程中被处理生成真正的 Gemfile。
# 使用 Gemfile.in 的好处是，它可以根据不同的环境或配置生成不同的 Gemfile 文件，从而满足不同的依赖管理需求。
#*****************************************************************************************************
module Proxy
  class BundlerHelper
    def self.require_groups(*groups)
      # 检查当前目录下是否存在 Gemfile.in 文件，来判断是否使用标准的 Gemfile 还是自定义的 Gemfile.in 来加载 Gem 依赖。
      if File.exist?(File.expand_path('../Gemfile.in', __dir__))
        # If there is a Gemfile.in file, we will not use Bundler but BundlerExt
        # gem which parses this file and loads all dependencies from the system
        # rathern then trying to download them from rubygems.org. It always
        # loads all gemfile groups.
        begin
          require 'bundler_ext' unless defined?(BundlerExt)   # 检查常量 BundlerExt 是否已经定义。
        rescue LoadError
          # Debian packaging guidelines state to avoid needing rubygems, so
          # we only try to load it if the first require fails (for RPMs)
          begin
            require 'rubygems' rescue nil
            require 'bundler_ext'
          rescue LoadError
            puts "`bundler_ext` gem is required to run smart_proxy"
            exit 1
          end
        end
        BundlerExt.system_require(File.expand_path('../Gemfile.in', __dir__), *groups)
      else
        require 'bundler' unless defined?(Bundler)
        #*****************************************************************************************
        # 例如:

        # group :development do
        #   gem 'pry', '~> 0.13.0'
        #   gem 'rubocop', '~> 1.10.0'
        # end
        #
        # 尽管 Bundler.require(:development) 已经加载了 pry 这个 gem，
        # 我们仍然需要在脚本中显式地使用 require 'pry'。这是因为虽然 Bundler.require 自动加载了 pry，
        # 但它并没有在当前作用域中直接导入 pry 这个 gem 的代码，只是确保它已经被加载。
        # 
        # Bundler.require 方法可以帮助你自动加载 Gem，而无需手动在代码中一个个地加载它们。
        # 用法:
        # 加载所有的 Gem:           Bundler.require
        #
        # 只加载特定的 Gem 组:      Bundler.require(:default, :development)
        # 
        # 根据环境加载不同的 Gem 组: Bundler.require(:default, (ENV['RACK_ENV'] || :development).to_sym)
        # 这个方法可以帮助你自动加载 Gem，而无需手动在代码中一个个地加载它们。
        #******************************************************************************************

        # 用于加载 Gemfile 中指定的 gem 组以及这些 gem 的依赖项。这个方法的主要功能是将 Gemfile 中列出的 gem 加载到你的应用程序中。
        Bundler.require(*groups)
      end
    end
  end
end
