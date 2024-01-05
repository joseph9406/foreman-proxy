require 'proxy/log'

"""
**** 处理信号（Signal）的安装和处理。*****
在 Unix 和 类Unix系统 中,进程可以向其他进程发送信号,以实现进程之间的通信或通知。
系统预留了一些信号编号,如SIGINT(中断信号,通常由Ctrl+C触发)和SIGTERM(终止信号,通常用于请求进程正常终止)等。

而 SIGUSR1 和 SIGUSR2 是两个用户自定义信号,用户可以根据需要在程序中使用它们。
SIGUSR1信号通常由用户用于向 "运行中的程序" 发送自定义命令或通知,
在該"運行中的程序"捕获到SIGUSR1信号之後,可以根据需要去执行特定的操作,如重新加载配置文件、执行特定的任务或切换程序的工作模式等。

如何生成 SIGUSR1信号 取决于操作系统和所使用的编程语言。在 Unix或 类Unix 系统中,可以使用 kill 命令向进程发送信号。
在Ruby中,可以使用Process.kill方法来发送信号。
例如;
  # 向进程ID为pid的进程发送SIGUSR1信号
  pid = 1234
  Process.kill('USR1', pid)
"""
class Proxy::SignalHandler
  include ::Proxy::Log

  def self.install_traps
    handler = new  # 表示创建了一个新的 Proxy::SignalHandler 对象，并将其赋值给变量 handler。
    handler.install_ttin_trap unless RUBY_PLATFORM =~ /mingw/
    handler.install_int_trap
    handler.install_term_trap
    handler.install_usr1_trap unless RUBY_PLATFORM =~ /mingw/
  end

  #***** 設置 ":TTIN" 信号处理器。*********************************************************************
  # trap方法 用於捕獲和處理信號, 在接收到指定的信号时,执行代码块中的代碼。语法形式为：trap(signal) { ... } 
  #   :INT 表示中斷信號
  #   :TERM 表示終止信號, 
  #   :TTIN 用户定义的信号，通常由操作系统发送给一个正在运行的进程，用于触发特定的操作。
  #*************************************************************************************************
  def install_ttin_trap
    # logger can't be accessed from trap context
    trap(:TTIN) do     
      puts "Starting thread dump for current Ruby process"
      puts "============================================="
      puts ""
      Thread.list.each do |thread|
        puts "Thread TID-#{thread.object_id}"  # object_id 方法获取线程对象的唯一标识符。
        puts thread.backtrace  # backtrace方法,获取线程的堆栈跟踪信息。
        puts ""  # 打印一个空行，以便在输出中添加换行符，使得每个线程的信息之间有一定的分隔。
      end
    end
  end

  #***** 設置 ":INT" 信号处理器。********************************************************************
  #  当接收到 SIGINT 信号时（通常由用户按下 Ctrl+C 触发），代码块中的内容将被执行。
  #  代码块中执行 exit(0)，即终止当前进程并返回退出状态码为 0。
  #*************************************************************************************************
  def install_int_trap
    # 中断信号(INT),通常由用户在终端上按下 Ctrl+C 或发送中断信号到进程时触发。
    # 接收到中断信号时，执行 exit(0)，以状态码 0 退出程序。即正常终止。
    # 这样做可以使程序在接收到中断信号时能够进行清理操作，并以合适的方式退出，而不是直接被终止。
    trap(:INT) { exit(0) } 
  end

  #***** 設置 :TERM 信号处理器。*********************************************************************
  #  当接收到 SIGTERM 信号时（通常由操作系统发送以终止进程），代码块中的内容将被执行。
  #  代码块中执行 exit(0)，即终止当前进程并返回退出状态码为 0。
  #*************************************************************************************************
  def install_term_trap
    # 终止信号通常由操作系统或其他外部实体发送给进程，用于请求进程终止并进行清理操作。
    trap(:TERM) { exit(0) }
  end

  #***** 設置 :USR1 信号处理器。**************************************************************************
  #  当接收到 SIGUSR1 信号时，代码块中的内容将被执行。
  #  代码块中调用了 ::Proxy::LogBuffer::Decorator.instance.roll_log = true，表示滚动日志，可能是用于日志处理。
  #******************************************************************************************************
  def install_usr1_trap
    trap(:USR1) do
      ::Proxy::LogBuffer::Decorator.instance.roll_log = true  # 将日志滚动的标志设置为 true。
    end
  end
end
