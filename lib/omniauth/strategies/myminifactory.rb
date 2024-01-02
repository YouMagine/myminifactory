require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class MyMiniFactory < OmniAuth::Strategies::OAuth2
      option :name, :myminifactory

      option :client_options, {
        site: 'https://auth.myminifactory.com',
        authorize_url: '/web/authorize',
        token_url: '/v1/oauth/tokens',
        introspect_url: '/v1/oauth/introspect'
      }

      uid { raw_info['user_id'] }

      info do
        {
          name: raw_info['username']
        }
      end

      def callback_url
#        'https://test.youmagine.com/users/auth/myminifactory/callback'
        "https://af05-153-92-40-143.ngrok-free.app"
      end

      def request_phase
        logger.info("Response: Status: #{response.status}, Body: #{response.body}")
        super
      end

      def callback_phase
        logger.info("MyMiniFactory Strategy - Starting callback phase.")
        super
      rescue StandardError => e
        logger.error("MyMiniFactory Strategy - Callback phase error: #{e.message}")
        raise
      end

      protected

      def logger
        @logger ||= Logger.new(STDOUT)
      end

      def raw_info
        logger.info("MyMiniFactory Strategy - Fetching raw info.")
        @raw_info ||= access_token.get("/user").parsed
      rescue StandardError => e
        logger.error("MyMiniFactory Strategy - Error fetching raw info: #{e.message}")
        raise
      end

      def mobile_login(access_token, device_info)
        response = client.request(:post, "#{options.client_options.site}/v1/oauth/mobile/login", {
          body: {
            client_key: client.id,
            access_token: access_token,
            device_info: device_info.to_json
          },
          headers: {'Content-Type' => 'application/x-www-form-urlencoded'}
        })
        parse_response(response)
      end

      def refresh_access_token(refresh_token)
        response = client.request(:post, options.client_options.token_url, {
          body: {
            grant_type: 'refresh_token',
            refresh_token: refresh_token
          },
          auth: [client.id, client.secret]
        })
        parse_response(response)
      end

      def token_introspection(token)
        response = client.request(:post, options.client_options.introspect_url, {
          body: {
            token: token,
            token_type_hint: 'access_token'
          },
          auth: [client.id, client.secret]
        })
        parse_response(response)
      end

      private

      def parse_response(response)
        if response.status != 200
          logger.error("MyMiniFactory Strategy - Non-successful response: Status #{response.status}, Body: #{response.body}")
        end
        response.parsed
      end
    end
  end
end
