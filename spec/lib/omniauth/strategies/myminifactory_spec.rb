
require 'spec_helper'
require 'webmock/rspec'
require 'omniauth/strategies/myminifactory'

RSpec.describe OmniAuth::Strategies::MyMiniFactory do
  let(:app) { lambda { |_env| [200, {}, ["Hello."]] } }
  subject do
    described_class.new(app, 'test_client', 'test_secret', 
      client_options: { 'site' => 'https://auth.myminifactory.com' })
  end

  before(:each) do
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  after(:each) do
    WebMock.allow_net_connect!
  end

  describe 'client options' do
    it 'has correct site' do
      expect(subject.options.client_options.site).to eq('https://auth.myminifactory.com')
    end

    it 'has correct authorize URL' do
      expect(subject.options.client_options.authorize_url).to eq('/web/authorize')
    end

    it 'has correct token URL' do
      expect(subject.options.client_options.token_url).to eq('/v1/oauth/tokens')
    end

    # Add more tests for other client options...
  end

  describe 'mobile login' do
    it 'requests the correct URL' do
      puts "DEBUG: client.options[:site] = #{subject.client.options[:site].inspect}"
      stub_request(:post, "https://auth.myminifactory.com/v1/oauth/mobile/login")
        .to_return(status: 200, body: "", headers: {})

      subject.mobile_login('access_token', { device_id: '1234' })

      expect(a_request(:post, "https://auth.myminifactory.com/v1/oauth/mobile/login")
        .with(body: hash_including({
          'client_key': 'test_client',
          'access_token': 'access_token',
          'device_info': '{"device_id":"1234"}'
        }))).to have_been_made.once
    end
  end
end
