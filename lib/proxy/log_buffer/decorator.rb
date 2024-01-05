require 'proxy/log_buffer/buffer'

module Proxy::LogBuffer
  class Decorator
    def self.instance
      # 使用了类变量 @@instance，在多线程环境下，多个线程同时访问 self.instance 方法时，只有一个线程会成功创建实例，其他线程会等待。这确保了单例实例的唯一性。
      @@instance ||= new(::Proxy::LoggerFactory.logger, ::Proxy::LoggerFactory.log_file) 
=begin
    如果将代码改为使用实例变量 @instance, 则可能存在竞态条件 (Race Condition)的风险。
    在多线程环境下，多个线程可以同时执行 self.instance 方法，可能会导致多次创建实例。
    为了确保单例实例的唯一性，你需要在 self.instance 方法中添加同步机制，以防止多个线程同时创建实例。

    @instance ||= begin
    Mutex.new.synchronize do
      @instance ||= new(::Proxy::LoggerFactory.logger, ::Proxy::LoggerFactory.log_file)
    end
    

    上述代码使用了 Mutex 对象来创建一个互斥锁, 确保只有一个线程可以进入临界区 (Mutex#synchronize 块），从而防止多次创建实例。
=end
    end

    attr_accessor :formatter, :roll_log
    alias_method :roll_log?, :roll_log  # alias_method :new_method_name, :existing_method_name 允许为一个已存在的方法创建一个别名

    def initialize(logger, log_file, buffer = Proxy::LogBuffer::Buffer.instance)
      @logger = logger
      @buffer = buffer
      @log_file = log_file
      @mutex = Mutex.new
      # self.roll_log = false; 这样做会调用对象的 attr_accessor 自动生成的 setter 方法，将值赋给实例变量 @roll_log。
      # 或是, @roll_log = false, 直接賦值給 @roll_log
      # 若是 roll_log = false, 則 roll_log 會被視為方法的局變,離開此方法的控制域就會消失,
      self.roll_log = false  
    end

    def add(severity, message = nil, progname = nil, exception_or_backtrace = nil)
      severity ||= UNKNOWN
      if message.nil?
        if block_given?  # block_given? 用于检查調用當前方法時,是否有附帶块传递给方法。
          message = yield  # 如果存在块，则通过 yield 执行块中的代码，以获取块的返回值，并将返回值赋给 message。
        else
          message = progname
        end
      end      
      #***************************************** formatter 到底從何處而來? *********************************************************       
      # "if formatter" 部分是一个条件语句，用于检查 formatter 是否存在。如果 formatter 存在（不为 nil 或 false），则执行前面的代码，否则跳过。
      # 这是为了处理可能没有指定 formatter 的情况，以防止出现异常。
      # 
      # 总的来说，这段代码的目的是使用指定的 formatter 对日志消息进行格式化处理，将日志消息转换为特定格式的字符串。这个格式化后的字符串
      # 会被后续的日志处理器记录下来，比如写入文件或输出到控制台。格式化的方式和具体的日志输出目标可能因项目而异，可以根据需要自定义 formatter 
      # 来满足特定的日志记录需求。
      #*****************************************************************************************************************************
      message = formatter.call(severity, Time.now.utc, progname, message) if formatter
      return if message == ''

      reopened = false
      @mutex.synchronize do
        if roll_log?
          # decorator is in-memory only, reopen underlaying logging appenders
          # ::Logging.reopen 是 Logging gem 提供的方法,用于重新打开日志文件以实现日志滚动（rolling）或 重新配置日志记录。
          # 当需要执行日志滚动（rolling）时，通常会调用 ::Logging.reopen 方法，根据一些条件(日期,文件大小...)切割日志,
          # 它会关闭当前的日志文件，然后重新打开一个新的日志文件,以便将新的日志记录进入新的日志文件。
          ::Logging.reopen  
          self.roll_log = false  # 類似開關,是为了控制滚动日志文件的行为。
          reopened = true  # 记录是否已重新打开日志文件的状态。
        end
        # add to the logger first
        @logger.add(severity, message)  
        # add to the buffer        
        if severity >= @logger.level    
          #================================= backtrace 的产生时机通常是在程序发生异常时 ==========================================================
          # 使用 begin...rescue...end 结构来创建"异常处理代码块",当程序执行过程中发生了异常（如 Ruby 中的异常或错误),异常处理机制会自动捕获异常信息,
          # 包括异常的类型、消息和发生异常的堆栈信息（backtrace）。
          # 例如;
          # 
          # begin         
          #   result = 10 / 0  # 除以零会引发异常
          # rescue ZeroDivisionError => e  #捕获 ZeroDivisionError 异常，  
          #    error_message = e.message  # 获取异常消息
          #    backtrace = e.backtrace   # 获取异常的回溯信息
          #    # 记录异常信息到日志, 日志的內容完全是自定義的,可以自行包含任何有意義的信息。
          #    @logger.add(::Logger::Severity::ERROR, "Error occurred: #{error_message}") 
          #    @logger.add(::Logger::Severity::ERROR, "Backtrace:\n#{backtrace.join("\n")}")
          #    result = nil
          # end 
          # puts "Result: #{result}" #后续代码继续执行
          #
          # exception_or_backtrace.is_a?(Exception), 判斷 exception_or_backtrace 是 Exception 类的实例,或者是其子类的实例。
          # exception_or_backtrace.backtrace; 其中, backtrace 用于存储日志消息的回溯信息,
          #   回溯信息通常包含了程序执行时的调用栈信息，用于帮助定位错误或异常发生的位置。
          #====================================================================================================================================
          backtrace = if exception_or_backtrace.is_a?(Exception) && !exception_or_backtrace.backtrace.nil?  # exception_or_backtrace.present?
                        exception_or_backtrace.message + ': ' + exception_or_backtrace.backtrace.join("\n")
                      #=========================================================================================================
                      # (1) 检查 backtrace 变量是否有 join 方法，如果有，则意味着 backtrace 可以被连接成一个字符串。
                      # (2) backtrace 变量在进入条件块之前还没有被赋值，因此它的初始值是 nil。
                      #     但是，elsif backtrace.respond_to?(:join) 仍然是合法的，因为在 Ruby 中，nil 对象也具有 respond_to? 方法。
                      #     然而,我覺得還是修改為 elsif exception_or_backtrace.respond_to?(:join) 比較合理。
                      #=========================================================================================================
                      # elsif backtrace.respond_to?(:join) 
                      elsif exception_or_backtrace.backtrace.respond_to?(:join) 
                        exception_or_backtrace.backtrace.join("\n")
                      else
                        exception_or_backtrace
                      end
          # 把產生的日志消息存入buffer中,這個動作是額外多動的,和產生日志本身沒有關係。
          rec = Proxy::LogBuffer::LogRecord.new(nil, severity, message.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'), backtrace, request_id)
          @buffer.push(rec)
        end
      end
      info("Logging file reopened via USR1 signal") if reopened
      # exceptions are also sent to structured log if available
      # "exception_or_backtrace&.is_a?(Exception)"; 判斷 exception_or_backtrace 是否是 Exception 類或其子類。
      exception("Error details for #{message}", exception_or_backtrace) if exception_or_backtrace&.is_a?(Exception)
    end

    def trace?
      @trace ||= !!ENV['FOREMAN_PROXY_TRACE']
    end

    def trace(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::DEBUG, nil, msg_or_progname, exception_or_backtrace, &block) if trace?
    end

    def debug(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::DEBUG, nil, msg_or_progname, exception_or_backtrace, &block)
    end

    def info(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::INFO, nil, msg_or_progname, exception_or_backtrace, &block)
    end
    alias_method :write, :info

    def warn(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::WARN, nil, msg_or_progname, exception_or_backtrace, &block)
    end
    alias_method :warning, :warn

    def error(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::ERROR, nil, msg_or_progname, exception_or_backtrace, &block)
    end

    def fatal(msg_or_progname = nil, exception_or_backtrace = nil, &block)
      add(::Logger::Severity::FATAL, nil, msg_or_progname, exception_or_backtrace, &block)
    end

    def request_id
      (r = ::Logging.mdc['request']).nil? ? r : r.to_s[0..7]
    end

    # Structured fields to log in addition to log messages. Every log line created within given block is enriched with these fields.
    # Fields appear in joruand and/or JSON output (hash named 'ndc').
    def with_fields(fields = {})     
      ::Logging.ndc.push(fields) do 
        yield    # yield 用于执行传递给方法的块。
      end
    end

    # Standard way for logging exceptions to get the most data in the log. By default
    # it logs via warn level, this can be changed via options[:level]
    def exception(context_message, exception, options = {})
      level = options[:level] || :warn
      # ::Logging::LEVELS 是一个哈希表，它将日志级别名称映射到其对应的整数值。例如，'INFO' 映射到 1，'WARN' 映射到 2，等等。
      # ::Logging::LEVELS.key?(level.to_s) 表示检查 level.to_s 是否存在于::Logging::LEVELS 的键集合中。
      unless ::Logging::LEVELS.key?(level.to_s)
        raise "Unexpected log level #{level}, expected one of #{::Logging::LEVELS.keys}"
      end
      # send class, message and stack as structured fields in addition to message string
      backtrace = exception.backtrace || []
      extra_fields = {
        exception_class: exception.class.name,
        exception_message: exception.message,
        exception_backtrace: backtrace,
      }
      extra_fields[:foreman_code] = exception.code if exception.respond_to?(:code)
      with_fields(extra_fields) do
        # 动态调用对象的公共（public）方法，类似于 send 方法。
        # 但与 send 不同，public_send 只能调用对象的公共方法，不能调用私有（private）方法或受保护（protected）方法。
        # 被調用的方法名称由 level 参数决定，例如，如果 level 是 :debug，那么就会调用 debug 方法。
        # public_send 后面附加一个块时，这个块会被传递给被调用的方法作为方法的参数。
        # 这里的 do ... end 块会被传递给由 level 决定的日志方法。具体来说，它会被传递给某个日志方法，例如 debug、info、warn 等。
        # 在方法内部，这个块会被执行，生成一条日志消息的内容。然后，这个内容会被传递给日志方法，用于记录日志。块的执行结果就是日志消息的内容。
        public_send(level) do  
          (["#{context_message}: <#{exception.class}>: #{exception.message}"] + backtrace).join("\n")
        end
      end
    end

    # method_missing 方法用于处理在对象上调用不存在的方法时的行为。
    # 当对象上调用一个不存在的方法时，Ruby 会自动调用 method_missing 方法，
    # 并将调用的方法名（symbol）以及传递给该方法的参数(*args)传递给 method_missing 方法。    
    def method_missing(symbol, *args)
      @logger.send(symbol, *args)
    end

  end
end
