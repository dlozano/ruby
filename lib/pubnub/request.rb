require 'pubnub/configuration.rb'
require 'pubnub/error.rb'
require 'pubnub/response.rb'

require 'openssl'
require 'digest/sha2'
require 'base64'

require 'json'

module Pubnub
  class Request
    include Pubnub::Configuration
    include Pubnub::Error

    attr_accessor :error_callback, :envelopes, :port, :timetoken, :operation, :response, :ssl, :channel, :callback, :cipher_key, :subscribe_key, :secret_key, :operation, :message, :publish_key
    attr_accessor :signature, :timestamp

    def initialize(options = {})
      @options = options

      @params         = options[:params]
      @operation      = options[:operation]
      @callback       = options[:callback]
      @error_callback = options[:error_callback]
      @error_callback = lambda { |x| puts "AN ERROR OCCURRED: #{x.msg}" } unless @error_callback
      @channel        = CGI.escape(options[:channel]).gsub('+','%20') if options[:channel]
      @message        = options[:message]
      @timetoken      = options[:timetoken] || "0"
      @timetoken      = options[:override_timetoken] if options[:override_timetoken]
      @ssl            = options[:ssl]
      @params         = options[:params]

      @history_limit  = options[:limit]

      @port           = options[:port]
      @host           = options[:origin]
      @query          = options[:query]

      set_cipher_key(options, @cipher_key) if %w(publish subscribe history).include? @operation
      set_message(options, @cipher_key) if %w(publish).include? @operation
      set_publish_key(options, @publish_key) if %w(publish audit grant).include? @operation
      set_subscribe_key(options, @subscribe_key) if %w(publish audit grant presence here_now history subscribe leave).include? @operation
      set_secret_key(options, @secret_key) if %w(publish subscribe audit grant).include? @operation

      if operation == 'audit' || operation == 'grant'
        generate_signature!
      end

    end

    def generate_signature!
      @timestamp = current_time
      message = "#{@subscribe_key}\n#{@publish_key}\n#{@operation}\n#{query}"
      @signature = CGI::escape(Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'), @secret_key, message)).strip())
      $log.debug @signature
      @signature
    end

    def current_time
      Time.now.to_i
    end

    def ssl=(ssl)
      if ssl
        @ssl = true
        @port = 443
      else
        @ssl = false
        @port = 80
      end
    end

    def origin
      if @ssl
        @origin = 'https://' + @host
        @port = 443
      else
        @origin = 'http://' + @host
        @port = 80
      end
      @origin
    end

    def path
      encode_path(case @operation
                    when 'audit'
                      [
                          'v1/auth',
                          @operation,
                          'sub-key',
                          @subscribe_key,
                      ]
                    when 'grant'
                      [
                          'v1/auth',
                          @operation,
                          'sub-key',
                          @subscribe_key,
                      ]
                   when 'publish'
                     [
                         @operation,
                         @publish_key,
                         @subscribe_key,
                         @secret_key,
                         @channel,
                         '0',
                         @message.to_json
                     ]
                   when 'subscribe'
                     [
                         @operation,
                         @subscribe_key,
                         @channel,
                         '0',
                         @timetoken
                     ]
                   when 'presence'
                     [
                         'subscribe',
                         @subscribe_key,
                         @channel.to_s + '-pnpres',
                         '0',
                         @timetoken
                     ]
                   when 'time'
                     [
                         @operation,
                         '0'
                     ]
                   when 'history'
                     [
                         'v2',
                         'history',
                         'sub-key',
                         @subscribe_key,
                         'channel',
                         @channel
                     ]
                    when 'here_now'
                      [
                          'v2',
                          'presence',
                          'sub-key',
                          @subscribe_key,
                          'channel',
                          @channel
                      ]
                    when 'leave'
                      [
                          'v2',
                          'presence',
                          'sub-key',
                          @subscribe_key,
                          'channel',
                          @channel
                      ]
                    else
                     raise("I can't create that URL for you due to unknown operation type.")
                 end
      )
    end

    def encode_path(request)
      path = URI.escape('/' + request.map{|i| i.to_s}.reject(&:empty?).join('/')).gsub(/\?/,'%3F')
      if @operation == 'leave'
        $log.debug "#{path}/leave"
        "#{path}/leave"
      else
        $log.debug path
        path
      end
    end

    def params
      flat = {}
      @params.each do |param,val|
        next if val.to_s.empty?
        flat[param.to_s] = val.to_s
      end
      flat
    end

    def query(options = {})
      params_hash = params.clone

      if @timestamp.present?
        params_hash.merge!({"timestamp" => @timestamp })

        if @channel.present?
          params_hash.merge!({"channel" => @channel })
        end
      end


      params_hash.merge!({"signature" => @signature}) if (options[:signature])

      params_hash.map do |param, value|
        [param, value].join('=')
      end.sort.join('&')
    end

    def handle_response(http)
      @response = nil

      if http.respond_to?(:body) && http.respond_to?(:code) && http.respond_to?(:message) && http.respond_to?(:headers) # httparty
        @response = JSON.load(http.body)
      else # em-http-request
        @response = http.response.respond_to?(:content) ? JSON.load(http.response.content) : JSON.load(http.response)
      end


      @last_timetoken = @timetoken
      @timetoken = @response[1] unless @operation == 'time'

      if @cipher_key.present? && %w(subscribe history).include?(@operation)

        response_array = Array.new
        crypto = Pubnub::Crypto.new(@cipher_key)

        if %w(subscribe history).include?(@operation)
          iteration = @response[0]
        else
          iteration = @response
        end

        if iteration.class == Array
          iteration.each do |msg|
            response_array << crypto.decrypt(msg)
          end if iteration
        elsif iteration.class == String
          response_array = [crypto.decrypt(iteration)]
        end

        case @operation
          when 'subscribe'
            @response[0] = response_array
          when 'history'
            json_response_data = JSON.load(http.response)
            @response = [response_array, json_response_data[1], json_response_data[2]]
        end
      end

      @envelopes = Array.new
      if %w(subscribe history).include? @operation
        @response.first.each_with_index do |res,index|
          @envelopes << Pubnub::Response.new(:http => http, :index => index, :response => @response, :channel => @channel, :operation => @operation, :path => path, :query => query)
        end
      else
        @envelopes << Pubnub::Response.new(:http => http, :channel => @channel, :response => @response, :operation => @operation, :path => path, :query => query)
      end
    end


    private

    def aes_encrypt(cipher_key, options, publish_request)

      pc = Pubnub::Crypto.new(cipher_key)
      publish_request.message = pc.encrypt(options[:message])

    end

    def set_cipher_key(options, self_cipher_key)
      if self_cipher_key.present? && options[:cipher_key].present?
        raise(OperationError, "existing cipher_key #{self_cipher_key} cannot be overridden at publish-time.")

      elsif (self_cipher_key.present? && options[:cipher_key].blank?) || (self_cipher_key.blank? && options[:cipher_key].present?)

        this_cipher_key = self_cipher_key || options[:cipher_key]
        raise(OperationError, 'secret key must be a string.') if this_cipher_key.class != String
        @cipher_key = this_cipher_key
      end
    end

    def set_secret_key(options, self_secret_key)
      if self_secret_key.present? && options[:secret_key].present?
        raise(OperationError, "existing secret_key #{self_secret_key} cannot be overridden at publish-time.")

      elsif (self_secret_key.present? && options[:secret_key].blank?) || (self_secret_key.blank? && options[:secret_key].present?)

        my_secret_key = self_secret_key || options[:secret_key]
        raise(OperationError, 'secret key must be a string.') if my_secret_key.class != String

        signature       = '{ @publish_key, @subscribe_key, @secret_key, channel, message}'
        digest          = OpenSSL::Digest.new('sha256')
        key             = [my_secret_key]
        hmac            = OpenSSL::HMAC.hexdigest(digest, key.pack('H*'), signature)
        @secret_key = my_secret_key
      else
        @secret_key = '0'
      end
    end

    def set_message(options, self_cipher_key)
      if options[:message].blank? && options[:message] != ''
        raise(OperationError, 'message is a required parameter.')
      else
        my_cipher_key = options[:cipher_key] || self_cipher_key

        if my_cipher_key.present?
          @message = aes_encrypt(my_cipher_key, options, self)
        else
          @message = options[:message]
        end
      end
    end

    def set_publish_key(options, self_publish_key)
      if options[:publish_key].blank? && self_publish_key.blank?
        raise(OperationError, 'publish_key is a required parameter.')
      elsif self_publish_key.present? && options[:publish_key].present?
        raise(OperationError, "existing publish_key #{self_publish_key} cannot be overridden at publish-time.")
      else
        @publish_key = (self_publish_key || options[:publish_key]).to_s
      end
    end

    def set_subscribe_key(options, self_subscribe_key)
      if options[:subscribe_key].blank? && self_subscribe_key.blank?
        raise(OperationError, 'subscribe_key is a required parameter.')
      elsif self_subscribe_key.present? && options[:subscribe_key].present?
        raise(OperationError, "existing subscribe_key #{self_subscribe_key} cannot be overridden at subscribe-time.")
      else
        @subscribe_key = (self_subscribe_key || options[:subscribe_key]).to_s
      end
    end

  end
end