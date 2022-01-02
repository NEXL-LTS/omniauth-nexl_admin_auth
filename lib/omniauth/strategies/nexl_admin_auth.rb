require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class NexlAdminAuth < OmniAuth::Strategies::OAuth2
      option :name, :nexl_admin_auth

      DEFAULT_SCOPE = 'openid email profile https://graph.microsoft.com/User.Read'.freeze

      option :client_options, {
        site: 'https://login.microsoftonline.com',
        authorize_url: '/fe932811-31eb-44e7-8325-ddaa213e0e14/oauth2/v2.0/authorize',
        token_url: '/fe932811-31eb-44e7-8325-ddaa213e0e14/oauth2/v2.0/token'
      }

      option :authorize_options, [:scope]

      info do
        { name: "#{raw_info['givenName']} #{raw_info['surname']}",
          email: raw_info['mail'],
          first_name: raw_info['givenName'],
          last_name: raw_info['surname'] }
      end

      uid { raw_info['id'] }

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('https://graph.microsoft.com/v1.0/me').parsed
      end

      def authorize_params
        super.tap do |params|
          %w[display score auth_type].each do |v|
            params[v.to_sym] = request.params[v] if request.params[v]
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
