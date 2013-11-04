require 'spec_helper'
require 'rr'
require 'vcr'

describe "Pam" do

  VCR.configure do |c|
    c.cassette_library_dir = 'fixtures/vcr_cassetttes'
    c.hook_into :webmock
  end

  before do
    @publish_key = 'pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa'
    @subscribe_key = 'sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe'
    @secret_key = 'sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz'
    @auth_key = 'myauthkey'
    @channel = "mychannel"
  end

  context "when an auth_key is provided" do

    before do
      @p = Pubnub.new(:subscribe_key => @subscribe_key, :publish_key => @publish_key, :secret_key => @secret_key)
    end

    context "when http_sync is true" do

      context "when a publish is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam1') do
            @p.publish(:channel => @channel, :message => @message, :http_sync => true)
          end

        end

      end

    end

    context "when http_sync is false"


  end


end
