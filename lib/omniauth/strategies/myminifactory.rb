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

      uid do
        logger.info("UID Raw Info: #{raw_info.inspect}")
        raw_info['user_id']
      end

      info do
        {
          name: raw_info['name'],
          username: raw_info['username'],
          email: raw_info['email'],
          profile_url: raw_info['profile_url'],
          avatar_url: raw_info['avatar_url']
        }
      end

      def authorize_params
        super.tap do |params|
          logger.info("Authorize Params: #{params.inspect}")
          session['omniauth.state'] = params[:state] if params[:state]
        end
      end

      def callback_phase
        logger.info("Entering Callback Phase")
        super
      rescue StandardError => e
        logger.error("Callback Phase Error: #{e.message}")
        raise
      end

      def callback_url
        url = options.callback_url || super
        logger.info("Callback URL: #{url}")
        url
      end

      protected

      def logger
        @logger ||= Logger.new(STDOUT)
      end

      def raw_info
        logger.info("Fetching Raw Info")
        @raw_info ||= access_token.get("https://www.myminifactory.com/api/v2/user").parsed.tap do |data|
          logger.info("Raw Info Received: #{data.inspect}")
        end
      rescue StandardError => e
        logger.error("Error Fetching Raw Info: #{e.message}")
        raise
      end
    end
  end
end
