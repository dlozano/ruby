require 'spec_helper'
require 'rr'
require 'vcr'

describe "PAM" do

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
    @message = "hello PAM world!"

    @err_callback = lambda { |x|
      puts "err callback: #{x}" }

    @msg_callback = lambda { |x|
      puts "msg callback: #{x}" }

    @p = Pubnub.new(:uuid => "myuuid", :subscribe_key => @subscribe_key, :publish_key => @publish_key, :secret_key => @secret_key, :error_callback => @err_callback)

  end

  context "when an auth_key is provided" do

    before do
      @p.auth_key = @auth_key
    end

    context "when http_sync is true (sync)" do

      context "when a publish is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam1', :record => :none) do
            response = @p.publish(:channel => @channel, :message => @message, :http_sync => true)
            response.request.params["auth"].should == @auth_key
          end
        end
      end

      context "when history is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam4', :record => :none) do
            response = @p.history(:channel => @channel, :count => 10, :http_sync => true)
            response.request.params["auth"].should == @auth_key
          end
        end
      end


      context "when subscribe is made" do

        context "on the initial subscribe" do
          it 'should provide the auth key in the url' do
            VCR.use_cassette('pam5', :record => :none) do
              response = @p.subscribe(:channel => @channel, :http_sync => true)
              response.request.params["auth"].should == @auth_key
            end
          end
        end


        context "on the initial and subsequent subscribe" do
          it 'should provide the auth key in the url' do
            VCR.use_cassette('pam6', :record => :none) do
              response1 = @p.subscribe(:channel => @channel, :http_sync => true)
              response2 = @p.subscribe(:channel => @channel, :http_sync => true)

              response1.request.params["auth"].should == @auth_key
              response2.request.params["auth"].should == @auth_key

            end
          end
        end
      end

    end

    context "when http_sync is false (async)" do




      context "when a publish is made" do

        before do
          mock(@p).verify_operation('publish', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                :origin => "pubsub.pubnub.com", :operation => "publish", :params => {:uuid => "myuuid", :auth => "myauthkey"}, :timetoken => nil,
                                                :error_callback => @err_callback, :channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback})
        end

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam3', :record => :none) do
            @p.auth_key = @auth_key
            @p.publish(:channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback)

          end
        end
      end


      context "when history is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam9', :record => :once) do
            response = @p.history(:channel => @channel, :count => 10, :http_sync => false)
            response.request.params["auth"].should == @auth_key
          end
        end
      end


      #context "when subscribe is made" do
      #
      #  context "on the initial subscribe" do
      #    it 'should provide the auth key in the url' do
      #      VCR.use_cassette('pam8', :record => :once) do
      #        response = @p.subscribe(:channel => @channel, :http_sync => false)
      #        response.request.params["auth"].should == @auth_key
      #      end
      #    end
      #  end
      #
      #
      #  context "on the initial and subsequent subscribe" do
      #    it 'should provide the auth key in the url' do
      #      VCR.use_cassette('pam7', :record => :once) do
      #        response1 = @p.subscribe(:channel => @channel, :http_sync => false)
      #        response2 = @p.subscribe(:channel => @channel, :http_sync => false)
      #
      #        response1.request.params["auth"].should == @auth_key
      #        response2.request.params["auth"].should == @auth_key
      #
      #      end
      #    end
      #  end
      #end


    end

  end











  context "when an auth_key is not provided" do

    before do
      @p = Pubnub.new(:subscribe_key => @subscribe_key, :publish_key => @publish_key, :secret_key => @secret_key)
    end

    context "when http_sync is true" do

      context "when a publish is made" do

        it 'should not provide an auth key in the url' do
          VCR.use_cassette('pam2', :record => :none) do
            response = @p.publish(:channel => @channel, :message => @message, :http_sync => true)
            response.request.params["auth"].should be_nil
          end
        end
      end
    end




  end

end
