#********************************************* logger庫 & logging庫 *************************************************
# 一、logger gem 是"Ruby标准库"中的一个日志记录模块，通常用于基本的日志记录需求。
#
# 二、logging gem 提供了一些高级功能和配置选项，这些功能在标准库中的 logger 模块中通常不可用。以下是一些 logging gem 的功能和优势：
# (1)多日志记录器支持：
#    logging gem 允许你创建多个不同的日志记录器，每个日志记录器可以有不同的配置和输出目标。这对于将日志消息分离到不同的记录器以进行更灵活的管理非常有用。
# (2)多输出目标：你可以将日志消息同时记录到多个输出目标，如文件、控制台、Syslog、远程服务器等。这使得在不同环境中更容易管理日志。
# (3)更多日志级别：logging gem 支持比标准的 logger 更多的日志级别，例如 debug1、debug2、debug3 等。这使得你可以更细粒度地控制日志的详细程度。
# (4)日志滚动：你可以配置日志滚动，以便按照文件大小或日期自动切分日志文件。这对于控制日志文件大小和历史记录保留非常有用。
# (5)多线程安全：logging gem 是多线程安全的，可以在多线程环境中安全地记录日志。
# (6)自定义日志格式：你可以轻松自定义日志消息的格式，以适应你的项目需求。这允许你在日志消息中包含特定的信息。
# (7)更多配置选项：logging gem 提供了丰富的配置选项，允许你更精细地控制日志记录行为，包括日志级别过滤、日志消息过滤、异常处理等。
#*****************************************************************************************************************************
require 'logging'
require 'proxy/log_buffer/decorator'
require 'proxy/time_utils'

module Proxy
  module Log
    def logger
      ::Proxy::LogBuffer::Decorator.instance
    end
  end

  class LoggerFactory
    BASE_LOG_SIZE = 1024 * 1024 # 1 MB
    #================================= "logging 庫" 和 "syslog/logger 庫" 的區別 =========================================
    # syslog/logger 是 Ruby 的另一个库，专门用于与系统日志服务集成。它提供了与 UNIX 和类 UNIX 系统的 syslog 服务通信的功能。 
    # 主要用于将应用程序的日志消息记录到系统的 syslog 服务，以便统一管理和监控系统级别的日志。
    # 这个库的优点在于;它可以将应用程序的日志与系统级别的日志集成在一起，方便系统管理员进行故障排查和监控。
    # 總結:
    # 如果你只需要在应用程序内部记录日志，并希望有更多的灵活性和控制，那么使用 logging 库可能更合适。
    # 如果你需要将应用程序的日志与系统级别的日志集成在一起，或者需要与 syslog 服务进行通信，那么使用 syslog/logger 库可能更合适。
    #====================================================================================================================
    begin      
      require 'syslog/logger' 
      @syslog_available = true
    rescue LoadError
      @syslog_available = false
    end    

    def self.logger
      logger_name = 'Joseph-logger'      
      # Logging::Layouts 是 Ruby 中的一个库，用于配置日志记录的布局。
      # pattern 方法是该库提供的一个方法，用來创建一个自定义的日志布局格式，该布局基于一个给定的模式（pattern）字符串。
      layout        = Logging::Layouts.pattern(pattern: ::Proxy::SETTINGS.file_logging_pattern + "\n")
      notime_layout = Logging::Layouts.pattern(pattern: ::Proxy::SETTINGS.system_logging_pattern + "\n")     
      #=======================================================================================================================
      # logging 库的用途是在"应用程序"中创建日志记录器來记录应用程序的运行状态和事件等日志消息,並設置日志的输出目标、级别、格式等。
      # 您可以创建一个根记录器，并为不同的模块创建子记录器。子记录器会继承其父记录器的设置，但也可以单独配置子記錄器。
      # << 這裏的父子繼承關係,僅說明子记录器会继承其父记录器的设置,記錄器所產生的內容存放,也是在設置中定義,內容本身不存在什麼繼承係。>>
      # 
      # 使用 Logging.logger.root 方法創建 "根日志记录器",
      #   在根记录器上的配置，例如日志级别、输出、格式等, 将应用于所有记录器上，包括 logging.logger 创建的记录器。 
      #   注意!!
      #   配置根日志记录器的输出为 STDOUT
      #   root_logger = Logging.logger.root
      #   root_logger.add_appenders Logging.appenders.stdout
      #   通過這樣的設定,才能讓子記錄器繼承根記錄器的輸出方式, 
      #   而然 root_logger = Logging.logger(STDOUT), 只能設定 root_logger 本身的輸出,無法繼承給子記錄器。
      # 
      # 使用 logger = Logging.logger['MyModule'] 程序员可以根据需要为不同的模块、组件或功能创建自定义的日志记录器，
      #   并为每个日志记录器指定一个名称。这个名称通常用于标识日志消息的来源。
      #   然而,自定义的日志记录器名称在日志消息输出中通常不会自动显示出来，除非你在消息格式中使用了占位符 %c 来显式包含它。
      #======================================================================================================================+
      logger = Logging.logger.root  

      # 依據條件 (log_file 的內容),将一个输出的附加器(Logging.appenders.XXX)添加到日志记录器中。            
      if log_file.casecmp('STDOUT').zero?  # casecmp('STDOUT');不考慮字母大小,比較 log_file 和 "STDOUT" 是否相同, 若相同,則返回 0.  
        if SETTINGS.daemon
          puts "若在守护进程模式下，表示应用程序在后台运行，通常不应将日志消息输出到标准输出,故在此情況下,输出一条错误消息并退出应用程序!"          
          puts "Settings log_file=STDOUT and daemon=true cannot be used together"
          exit(1)
        end        
        #================================ Logging.appenders.xxx(logger_name, layout => layout) =====================================
        # 用于配置一个现有的日志记录器（通过 Logging.logger 创建的）的输出位置和格式。
        # logger_name：这是一个字符串，用于标识日志记录器的名称。每个日志记录器通常都有一个唯一的名称，以便识别不同部分或组件生成的日志消息。
        # layout: 这是一个布局（layout）配置，用于定义日志消息的格式。layout 是一个变量，它应该包含了消息格式的定义。
        #         例如，可以定义日志消息的时间戳、日志级别、消息文本等内容的排列方式。
        # 再用 logger.add_appenders(...); 将該附加器添加到日志记录器。
        # 
        # 將 logger 和 appender 關聯起來;
        # logger = Logging.logger['my_logger'] # 創建一個日志記錄器,名稱是"my_logger"
        # appender = Logging.appenders.stdout('stdout', layout: Logging.layouts.pattern(pattern: '%d [%l] %m\n'))
        # logger.add_appenders(appender)  # 用它們的變量而不是用"唯一標識"來關聯。
        #==========================================================================================================================
        logger.add_appenders(Logging.appenders.stdout(logger_name, layout: layout))
      elsif log_file.casecmp('SYSLOG').zero?
        unless syslog_available?  # syslog_available? 是否支持系统日志功能。
          puts "Syslog is not supported on this platform, use STDOUT or a file"
          exit(1)
        end
        #==================================== Syslog 设备 ================================================
        # 在Syslog中，"设备"（facility）是一种用于标识和分类不同类型的日志消息的机制。
        # Syslog使用了一组预定义的设备（facility），每个设备都对应于一种特定类型的日志消息,的目的是将日志消息分组，
        # 以便根据其类型将它们记录到不同的位置或采取不同的处理方式。一些常见的Syslog设备包括：
        #  (1) LOG_KERN：用于内核消息，通常不由应用程序生成。
        #  (2) LOG_USER：用于一般用户级别的消息，这是应用程序通常使用的设备。
        #  (3) LOG_MAIL：用于邮件系统的消息。
        #  (4) LOG_AUTH：用于身份验证和安全相关的消息。
        #  (5) LOG_LOCAL0 到 LOG_LOCAL7：这些是本地使用的设备，通常由应用程序自定义以记录特定类型的消息。
        # Syslog 设备通常不直接指定输出位置，而是根据Syslog 守护程序的配置来确定日志消息的记录位置。
        # 不同的设备可能会被记录到不同的系统日志文件中，或者可以通过配置将它们发送到远程 Syslog 服务器。
        #===================================================================================================
        logger.add_appenders(Logging.appenders.syslog(logger_name, layout: notime_layout, facility: ::Syslog::Constants::LOG_LOCAL5))      
      elsif log_file.casecmp('JOURNAL').zero? || log_file.casecmp('JOURNALD').zero?  # 是否要将日志输出到系统日志的 journal（日志系统）。
        begin          
          logger.add_appenders(Logging.appenders.journald(
            logger_name, logger_name: :proxy_logger, layout: notime_layout, facility: ::Syslog::Constants::LOG_LOCAL5))
        rescue NoMethodError
          logger.add_appenders(Logging.appenders.stdout(logger_name, layout: layout))
          logger.warn "Journald is not available on this platform. Falling back to STDOUT."
        end
      else
        begin
          keep = ::Proxy::SETTINGS.file_rolling_keep
          # 表示日志文件的大小阈值。这里使用了一个基础的日志文件大小 BASE_LOG_SIZE 乘以设置中的 file_rolling_size 参数来计算实际的大小阈值。
          size = BASE_LOG_SIZE * ::Proxy::SETTINGS.file_rolling_size
          age = ::Proxy::SETTINGS.file_rolling_age  # 获取日志文件滚动的参数 age，它表示日志文件的最大保存时间（按天计算）。
          if size > 0  # 如果 size 大于零，表示要启用日志文件滚动，以按大小滚动日志文件。
            logger.add_appenders(Logging.appenders.rolling_file(logger_name, layout: layout, filename: log_file, keep: keep, size: size, age: age, roll_by: 'date'))
          else
            # 表示不启用日志文件滚动，那么会使用 Logging.appenders.file 方法创建一个普通文件日志附加器,并将其添加到日志记录器中。
            # 这个附加器将把所有的日志消息追加到同一个文件中,不会按大小滚动。
            logger.add_appenders(Logging.appenders.file(logger_name, layout: layout, filename: log_file))
          end
        rescue ArgumentError => ae  # ArgumentError 表示当方法接收到的参数不符合其期望参数的数量或类型时引发的异常,并将其存储在变量 ae 中
          logger.add_appenders(Logging.appenders.stdout(logger_name, layout: layout))
          logger.warn "Log file #{log_file} cannot be opened. Falling back to STDOUT: #{ae}"
        end
      end

      logger.level = ::Logging.level_num(::Proxy::SETTINGS.log_level) # ::Logging.level_num; 用于将日志级别名称（例如 "INFO"、"DEBUG"、"ERROR" 等）转换为对应的数字表示。
      logger
    end

    def self.syslog_available?
      !!@syslog_available  # 如果 @syslog_available 是 true、false 或 nil 中的任何一个，都将被转换为相应的布尔值。
    end

    def self.log_file
      @log_file ||= ::Proxy::SETTINGS.log_file
    end
  end

  class LoggerMiddleware
    include Log
    include ::Proxy::TimeUtils

    def initialize(app)
      @app = app      
      @max_body_size = ENV['FOREMAN_LOG_MAX_BODY_SIZE'] || 2000  
    end

    def call(env)
      # 这行代码用于获取当前时刻的高精度时间戳，并将其存储在 before 变量中,用于记录请求处理开始的时间点。
      # Process.clock_gettime 是 Ruby 中用于获取时钟时间的方法。
      # Process::CLOCK_MONOTONIC 是时钟类型的一个标识符，表示一个不受系统时间更改影响的单调时钟,适用于性能测量和计时操作。
      before = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      status = 500
      env['rack.logger'] = logger  # 将当前的 logger 对象赋值给 env['rack.logger'] ，这样后续的请求处理代码可以使用这个 logger 记录日志。
      logger.info { "Started #{env['REQUEST_METHOD']} #{env['REQUEST_PATH']} #{env['QUERY_STRING']}" } # 使用代码块生成的消息来记录信息级别的日志。
      # 表示使用 logger 记录 TRACE 级别的日志信息。TRACE 级别通常用于记录详细的调试信息。
      # 记录请求头部信息，只包括以 'HTTP_' 开头的键。这些是 HTTP 请求头部。
      logger.trace { 'Headers: ' + env.select { |k, v| k.start_with? 'HTTP_' }.inspect }  # 在块内可以编写代码来生成或计算需要记录的日志消息。
      #******************************************************************************************
      # 这段代码的目的是检查请求是否包含主体数据，并在包含主体数据的情况下,将输入流重新定位到起始位置，
      # 以便后续的代码或中间件能够读取和处理这些数据。
      #
      # env['rack.input']：該 Rack 环境变量，用于表示请求的输入流,即表示这个输入流的对象。
      # 在 HTTP 请求中，请求主体（例如 POST 请求中的表单数据或 JSON 数据）通常会作为输入流传递给服务器端。
      #*******************************************************************************************
      logger.trace do 
        # 從输入流中读取请求主体的内容，并将内容赋给 body 变量。这样，body 变量就包含了请求主体的数据。
        if env['rack.input'] && !(body = env['rack.input'].read).empty?
          env['rack.input'].rewind   # 将输入流重新定位到流的起始位置。
          if env['CONTENT_TYPE'] == 'application/json' && body.size < @max_body_size
            "Body: #{body}"
          elsif env['CONTENT_TYPE'] == 'text/plain' && body.size < @max_body_size
            "Body: #{body}"
          else
            "Body: [filtered out]"
          end
        else
          ''
        end
      end
      status, _, _ = @app.call(env)
    rescue Exception => e
      logger.exception "Error processing request '#{::Logging.mdc['request']}", e
      raise e
    ensure
      logger.info do        
        after = Process.clock_gettime(Process::CLOCK_MONOTONIC)   # 用于记录请求处理結束的时间点。
        duration = (after - before) * 1000
        "Finished #{env['REQUEST_METHOD']} #{env['REQUEST_PATH']} with #{status} (#{duration.round(2)} ms)"
      end
    end
  end
  
end
