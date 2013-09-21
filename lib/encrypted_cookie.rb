require 'openssl'
require 'rack/request'
require 'rack/response'
require 'encrypted_cookie/encryptor'

module Rack
  module Session
    # Rack::Session::EncryptedCookie provides AES-256-encrypted, tamper-proof
    # cookie-based session management.
    class EncryptedCookie
      def initialize(app) #TODO: GJ: allow overriding of default options
        @app = app
      end

      def call(env)
        options = env['restpack.session.options'].dup

        unless options[:secret]
          fail "Error! env['rack.session.options'][:secret] is required to use encrypted cookies."
        end

        options[:key] ||= "restpack.session"
        options[:path] ||= "/"

        encryptor = Encryptor.new(options[:secret])

        load_session(env, encryptor, options)
        status, headers, body = @app.call(env)
        commit_session(env, encryptor, options, status, headers, body)
      end

      private

      def load_session(env, encryptor, options)
        request = Rack::Request.new(env)
        session_data = request.cookies[options[:key]]

        if session_data
          session_data = encryptor.decrypt(session_data)
        end

        begin
          session_data = Marshal.load(session_data)
          env["restpack.session"] = session_data
        rescue
          env["restpack.session"] = Hash.new
        end
      end

      def commit_session(env, encryptor, options, status, headers, body)
        session_data = Marshal.dump(env["restpack.session"])
        session_data = encryptor.encrypt(session_data)

        if session_data.size > (4096 - options[:key].size)
          env["rack.errors"].puts("Warning! Rack::Session::Cookie data size exceeds 4K. Content dropped.")
        else
          cookie = Hash.new
          cookie[:value] = session_data
          cookie[:expires] = Time.now + options[:expire_after] unless options[:expire_after].nil?
          Utils.set_cookie_header!(headers, options[:key], cookie.merge(options))
        end

        [status, headers, body]
      end
    end
  end
end
