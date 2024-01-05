require 'date'
require 'proxy/log_buffer/ring_buffer'

# Adopted from Celluloid library (ring_buffer.rb).
# Copyright (c) 2011-2014 Tony Arcieri. Distributed under the MIT License.
# https://github.com/celluloid/celluloid/blob/0-16-stable/lib/celluloid/logging/ring_buffer.rb
module Proxy::LogBuffer
  # 在Ruby中，当你调用 Struct.new 创建一个结构体时，你可以传递一个可选的块（block）来自定义结构体的行为和方法。
  # 这个块会在结构体被创建时执行一次，允许你添加额外的自定義方法或行为到结构体中。
  # 如下代碼所示;
  # 在块中定义了一个自定义方法 to_h，这个 to_h 方法在后续可以被 LogRecord 的实例调用，
  LogRecord = Struct.new(:timestamp, :level, :message, :backtrace, :request_id) do    
    def to_h
      h = {}
      # 方法中的 self 是指該方法的"調用者"; 所以,這裏是指 LogRecord 结构体所產生的实例。
      # self.class 是 LogRecord 结构体的类对象，self.class.members 返回了 LogRecord 结构体中的所有成员的名称，它是一个数组。
      self.class.members.each { |m| h[m.to_sym] = self[m] }    # 將 LogRecord 的實例轉為 hash
      h[:level] = case h[:level]
                  when ::Logger::Severity::INFO
                    :INFO
                  when ::Logger::Severity::WARN
                    :WARN
                  when ::Logger::Severity::ERROR
                    :ERROR
                  when ::Logger::Severity::FATAL
                    :FATAL
                  when ::Logger::Severity::DEBUG
                    :DEBUG
                  else
                    :UNKNOWN
                  end
      h.delete(:backtrace) unless h[:backtrace]
      h.delete(:request_id) unless h[:request_id]
      h
    end
  end

  class Buffer
    def self.instance   # 此處的self表示該方法是類方法
      @@buffer ||= Buffer.new
    end

    def initialize(size = nil, size_tail = nil, level_tail = nil)
      @mutex = Mutex.new
      @failed_modules = {}
      @main_buffer = RingBuffer.new(size || ::Proxy::SETTINGS.log_buffer.to_i)
      @tail_buffer = RingBuffer.new(size_tail || ::Proxy::SETTINGS.log_buffer_errors.to_i)
      @level_tail = level_tail || ::Logger::Severity::ERROR
    end

    def push(rec)
      @mutex.synchronize do
        rec.timestamp = Time.now.utc.to_f
        old_value = @main_buffer.push(rec)
        @tail_buffer.push(old_value) if old_value && old_value.level >= @level_tail
      end
    end

    def iterate_ascending
      @mutex.synchronize do
        @tail_buffer.iterate_ascending { |x| yield x }
        @main_buffer.iterate_ascending { |x| yield x }
      end
    end

    def iterate_descending
      @mutex.synchronize do
        @main_buffer.iterate_descending { |x| yield x }
        @tail_buffer.iterate_descending { |x| yield x }
      end
    end

    def to_a(from_timestamp = 0)
      result = []
      if from_timestamp == 0
        iterate_ascending do |x|
          result << x if x
        end
      else
        iterate_ascending do |x|
          result << x if x && x.timestamp >= from_timestamp
        end
      end
      result
    end

    # Singleton logger does not allow per-module logging, until this is fixed
    # initialization errors are kept in this explicit hash.
    def failed_module(a_module, message)
      @failed_modules[a_module] = message
    end

    def size
      @main_buffer.size
    end

    def size_tail
      @tail_buffer.size
    end

    def to_s
      "#{size}/#{size_tail}"
    end

    def info
      {
        :size => size,
        :tail_size => size_tail,
        :level => @level,
        :level_tail => @level_tail,
        :failed_modules => @failed_modules,
      }
    end
  end
end
