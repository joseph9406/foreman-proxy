require 'net/http'
require 'net/https'
require 'uri'
require 'cgi'

module Proxy::HttpRequest
  # 創建客戶端請求 (get request, post request)
  class ForemanRequestFactory
    def initialize(base_uri)
      @base_uri = base_uri
    end

    # 將 hash 轉換為 URL 查詢字串(query string)
    # params = { :limit => 10, :page => 3 }; uri.query = URI.encode_www_form(params) 也可以將 hash 直接轉為 query string,並有轉義功能,所以可以用此方法代替。
    def query_string(input = {})
      # CGI.escape 是 Ruby 的 CGI 模組提供的一個方法，用於對字符串進行 URL 轉義(將字符串中的特殊字符轉換為它們的URL安全形式)。
      # 比如 ,CGI.escape("Hello, World!")   # => "Hello%2C+World%21", 空格被轉換成"+"，逗號被轉換成 %2C，感嘆號被轉換成 %21 ...      
      # compact 移除数组或哈希中的所有 nil 元素。例如; { k1: 'value1', k2: nil, k3: 'value3' }.compact => { k1: 'value1', k3: 'value3' }
      input.compact.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v)}" }.join("&")
    end

    # 用於創建並配置一個 HTTP GET 請求對象 (Net::HTTP::Get)。
    def create_get(path, query = {}, headers = {})
      uri = uri(path)    # 创建一个 URI 对象,表示请求的目标地址(server端的uri)
      # 使用 Net::HTTP::Get.new 創建一個 HTTP GET 請求對象。
      req = Net::HTTP::Get.new( "#{uri.path || '/'}?#{query_string(query)}" )  # uri.path || '/'; 若 uri.path 為空，則使用 / 作為默認值。
      req = add_headers(req, headers)
      req
    end

    def uri(path)
      URI.join(@base_uri.to_s, path)  # 使用 URI.join 方法將 @base_uri 和 path 這兩個字符串,組合成一個新的 URI。該方法會處理相對路徑和絕對路徑的合併。
    end

    def add_headers(req, headers = {})
      # req.add_field 是用于向 HTTP 请求（req）的头部（headers）中添加字段的方法。
      # 'Accept'是 HTTP 请求头的一个标准字段，用于告知服务器客户端能够处理的媒体类型。
      # 这是一个常见的用法，特别是在与 RESTful API 通信的场景中。
      # 通过设置 Accept 头，客户端可以明确告知服务器它所期望的响应格式，以确保服务器返回符合客户端期望的数据类型。
      req.add_field('Accept', 'application/json,version=2') 
      # 如果 headers 散列中存在 Content-Type 這個鍵值對，則 headers.delete("Content-Type") 會先返回該鍵值對的值，再將該鍵值對對從 headers hash 中刪除。
      # headers.delete("Content-Type"), 刪除headers["Content-Type"]整組鍵值對, 刪除時,會返回該鍵的值。所以該返回值會賦值給 req.content_type
      req.content_type = headers.delete("Content-Type") || 'application/json'    # application/json: 这是媒体类型的值，表示实体主体是 JSON 格式的数据。
      headers.each do |k, v|
        req.add_field(k, v)
      end
      req
    end

    def create_post(path, body, headers = {}, query = {})
      uri = uri(path)
      uri.query = query_string(query)
      req = Net::HTTP::Post.new(uri)
      req = add_headers(req, headers) # POST 請求通常需要在請求主體中攜帶資料（payload），所以該行代碼的作用是將 body 參數的內容賦值給 POST 請求對象的請求主體。
      req.body = body
      req
    end
  end

  # 創建連線對象和發送客戶端請求
  class ForemanRequest
    def send_request(request)
      http.request(request)  # 使用 http 對象的 request 方法發送一個 HTTP 請求。
    end

    def request_factory
      ForemanRequestFactory.new(uri)
    end

    def uri
      @uri ||= URI.parse(Proxy::SETTINGS.foreman_url.to_s)
    end

    def http
      @http ||= http_init
    end

    private

    def http_init
      # 初始化一個 Net::HTTP 對象，並設置了目標服務器的主機名和端口號。這是建立與服務器的連接的第一步。
      http             = Net::HTTP.new(uri.host, uri.port)  
      http.use_ssl     = uri.scheme == 'https'   # scheme 表示 URL 的协议部分，通常是 URL 开头的部分, 例如，在 https://example.com 中，https 就是协议（scheme）
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      if http.use_ssl?
        ca_file = Proxy::SETTINGS.foreman_ssl_ca || Proxy::SETTINGS.ssl_ca_file
        certificate = Proxy::SETTINGS.foreman_ssl_cert || Proxy::SETTINGS.ssl_certificate
        private_key = Proxy::SETTINGS.foreman_ssl_key || Proxy::SETTINGS.ssl_private_key

        if ca_file && !ca_file.to_s.empty?
          http.ca_file     = ca_file
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end

        if certificate && !certificate.to_s.empty? && private_key && !private_key.to_s.empty?
          http.cert = OpenSSL::X509::Certificate.new(File.read(certificate))
          http.key  = OpenSSL::PKey::RSA.new(File.read(private_key), nil)
        end
      end
      http
    end
  end
end
