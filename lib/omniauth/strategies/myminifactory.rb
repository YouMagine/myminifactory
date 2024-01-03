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
          name: raw_info['name'],  # 'name' field for the full name
          username: raw_info['username'],
          email: raw_info['email'],
          profile_url: raw_info['profile_url'],
          avatar_url: raw_info['avatar_url']
        }
      end

      def callback_url
        'https://test.youmagine.com/users/auth/myminifactory/callback'
        # "https://af05-153-92-40-143.ngrok-free.app/users/auth/myminifactory/callback"
      end

      def request_phase
        # Build the full URL for the authorization request
        url = callback_url

        # Add query parameters to the URL
        options.authorize_params[:response_type] = 'code'
        options.authorize_params[:redirect_uri] = callback_url

        # Generate the full authorization URL with query parameters
        url += "?#{options.authorize_params.to_query}"

        # Log the full URL
        logger.info("Authorization URL: #{url}")

        # Proceed with the regular request phase
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

        # Use the updated API endpoint for user information
        response = access_token.get("https://www.myminifactory.com/api/v2/user")

        if response.status != 200
          logger.error("MyMiniFactory Strategy - Non-successful response: Status #{response.status}, Body: #{response.body}")
          raise "Failed to fetch user info: #{response.body}"
        end

        response.parsed
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
        parsed_response = parse_response(response)
        logger.info("Parsed Response: #{parsed_response}")

      end

      def refresh_access_token(refresh_token)
        response = client.request(:post, options.client_options.token_url, {
          body: {
            grant_type: 'refresh_token',
            refresh_token: refresh_token
          },
          auth: [client.id, client.secret]
        })
        parsed_response = parse_response(response)
        logger.info("Parsed Response: #{parsed_response}")
      end

      def token_introspection(token)
        response = client.request(:post, options.client_options.introspect_url, {
          body: {
            token: token,
            token_type_hint: 'access_token'
          },
          auth: [client.id, client.secret]
        })
        parsed_response = parse_response(response)
        logger.info("Parsed Response: #{parsed_response}")
      end

      private

      def parse_response(response)
        if response&.status != 200
          logger.error("MyMiniFactory Strategy - Non-successful response: Status #{response&.status}, Body: #{response.body}")
        end
        response.parsed
      end
    end
  end
end
