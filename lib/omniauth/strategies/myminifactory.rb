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

      def authorize_params
        super.tap do |params|
          params[:google_login] = 'true'
          csrf_token = session['omniauth.state']
          logger.info("CSRF Token (state) generated: #{csrf_token}")
          logger.debug("Session contents after generating CSRF Token: #{session.inspect}")
          verify_rails_csrf_token!
        end
      end

      def callback_phase
        logger.debug("Session contents at start of callback_phase: #{session.inspect}")
        csrf_token_sent = request.params['state']
        csrf_token_expected = session.delete('omniauth.state')
        logger.info("CSRF Token (state) received: #{csrf_token_sent}")
        logger.info("CSRF Token (state) expected: #{csrf_token_expected}")
        logger.info("CSRF Token matches: #{csrf_token_sent == csrf_token_expected}")
        logger.debug("Request params: #{request.params.inspect}")

        if csrf_token_expected != csrf_token_sent
          logger.error("CSRF Token mismatch: expected #{csrf_token_expected}, got #{csrf_token_sent}")
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF token mismatch"))
        end

        super
      end

      def callback_url
        options.callback_url || 'https://www.example.com/url'
      end

      protected

      def verify_rails_csrf_token!
        # Fetch the CSRF token from the session
        rails_csrf_token = session[:_csrf_token]
        # Fetch the CSRF token sent in the form
        form_csrf_token = request.params['authenticity_token']

        logger.info("Rails CSRF Token from session: #{rails_csrf_token}")
        logger.info("Rails CSRF Token from form: #{form_csrf_token}")

        # Check if the tokens match
        if form_csrf_token.blank? || form_csrf_token != rails_csrf_token
          logger.error("Rails CSRF Token mismatch or missing")
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "Rails CSRF token mismatch or missing"))
        end
      end

      def logger
        @logger ||= Logger.new(STDOUT)
      end

      def raw_info
        # Use the updated API endpoint for user information
        response = access_token.get("https://www.myminifactory.com/api/v2/user")
        log_response(response, "Fetching user info")

        response.parsed
      rescue StandardError => e
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
      end

      private

      def parse_response(response)
        log_response(response, "Parsing response")
        response.parsed
      end

      def log_response(response, action)
        if response&.status != 200
          logger.error("#{action} - Non-successful response: Status #{response&.status}, Body: #{response.body}")
        else
          logger.debug("#{action} - Response: #{response.parsed.inspect}")
        end
      end
    end
  end
end
