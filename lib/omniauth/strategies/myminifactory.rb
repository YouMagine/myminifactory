# frozen_string_literal: true

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
          name: raw_info['name'],
          username: raw_info['username'],
          email: raw_info['email'],
          profile_url: raw_info['profile_url'],
          avatar_url: raw_info['avatar_url']
        }
      end

      def authorize_params
        super.tap do |params|
          # Custom parameters can be added here if required by the OAuth provider
          session['omniauth.state'] = params[:state] if params[:state]
        end
      end

      def callback_phase
        super
      end

      def callback_url
        options.callback_url || super
      end

      protected

      def logger
        @logger ||= Logger.new(STDOUT)
      end

      def raw_info
        @raw_info ||= access_token.get("https://www.myminifactory.com/api/v2/user").parsed
      end
    end
  end
end
