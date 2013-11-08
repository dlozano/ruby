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
    @origin = "pam-next.devbuild.pubnub.com"

    @err_callback = lambda { |x|
      puts "err callback: #{x}" }

    @msg_callback = lambda { |x|
      puts "msg callback: #{x}" }


    @logger = Logger.new(STDERR)

    @p = Pubnub.new(:origin => @origin, :uuid => "myuuid", :subscribe_key => @subscribe_key, :publish_key => @publish_key, :secret_key => @secret_key, :error_callback => @err_callback)

  end

  describe "with auth set" do

    before do
      @p.auth_key = @auth_key
    end

    context "synchronously" do

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


    context "asynchronously" do

      context "when a publish is made" do


        it 'should provide the auth key in the url' do

          mock(@p).verify_operation('publish', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                :origin => @origin, :operation => "publish", :params => {:uuid => "myuuid", :auth => "myauthkey"}, :timetoken => nil,
                                                :error_callback => @err_callback, :channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback})


          VCR.use_cassette('pam3', :record => :none) do
            @p.auth_key = @auth_key
            @p.publish(:channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback)

          end
        end
      end


      context "when history is made" do

        it 'should provide the auth key in the url' do

          mock(@p).verify_operation('history', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                :origin => @origin, :operation => "history", :params => {:uuid => "myuuid", :auth => "myauthkey"}, :timetoken => nil,
                                                :error_callback => @err_callback, :channel => @channel, :count => 10, :http_sync => false, :callback => @msg_callback})


          VCR.use_cassette('pam9', :record => :none) do
            @p.history(:channel => @channel, :count => 10, :http_sync => false, :callback => @msg_callback)
          end
        end
      end

      context "when subscribe is made" do

        context "on the initial subscribe" do
          it 'should provide the auth key in the url' do

            mock(@p).verify_operation('subscribe', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                    :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                    :origin => @origin, :operation => "subscribe", :params => {:uuid => "myuuid", :auth => "myauthkey"}, :timetoken => nil,
                                                    :error_callback => @err_callback, :channel => @channel, :http_sync => false, :callback => @msg_callback})

            VCR.use_cassette('pam8', :record => :none) do
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)
            end
          end
        end


        context "on the initial and subsequent subscribe" do
          it 'should provide the auth key in the url' do

            mock(@p).verify_operation('subscribe', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                    :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                    :origin => @origin, :operation => "subscribe", :params => {:uuid => "myuuid", :auth => "myauthkey"}, :timetoken => nil,
                                                    :error_callback => @err_callback, :channel => @channel, :http_sync => false, :callback => @msg_callback}).times(2)

            VCR.use_cassette('pam7', :record => :none) do
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)


            end
          end
        end
      end
    end
  end


  describe "with no auth set" do

    before do
      @p.auth_key = nil
    end

    context "synchronously" do

      context "when a publish is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam1', :record => :none) do
            response = @p.publish(:channel => @channel, :message => @message, :http_sync => true)
            response.request.params["auth"].should be_nil
          end
        end
      end

      context "when history is made" do

        it 'should provide the auth key in the url' do
          VCR.use_cassette('pam4', :record => :none) do
            response = @p.history(:channel => @channel, :count => 10, :http_sync => true)
            response.request.params["auth"].should be_nil
          end
        end
      end


      context "when subscribe is made" do

        context "on the initial subscribe" do
          it 'should provide the auth key in the url' do
            VCR.use_cassette('pam5', :record => :none) do
              response = @p.subscribe(:channel => @channel, :http_sync => true)
              response.request.params["auth"].should be_nil
            end
          end
        end


        context "on the initial and subsequent subscribe" do
          it 'should provide the auth key in the url' do
            VCR.use_cassette('pam6', :record => :none) do
              response1 = @p.subscribe(:channel => @channel, :http_sync => true)
              response2 = @p.subscribe(:channel => @channel, :http_sync => true)

              response1.request.params["auth"].should be_nil
              response2.request.params["auth"].should be_nil

            end
          end
        end

      end

    end


    context "asyncronously" do

      context "when a publish is made" do


        it 'should provide the auth key in the url' do

          mock(@p).verify_operation('publish', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                :origin => @origin, :operation => "publish", :params => {:uuid => "myuuid", :auth => nil}, :timetoken => nil,
                                                :error_callback => @err_callback, :channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback})


          VCR.use_cassette('pam3', :record => :none) do
            @p.publish(:channel => @channel, :message => @message, :http_sync => false, :callback => @msg_callback)

          end
        end
      end


      context "when history is made" do

        it 'should provide the auth key in the url' do

          mock(@p).verify_operation('history', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                :origin => @origin, :operation => "history", :params => {:uuid => "myuuid", :auth => nil}, :timetoken => nil,
                                                :error_callback => @err_callback, :channel => @channel, :count => 10, :http_sync => false, :callback => @msg_callback})


          VCR.use_cassette('pam9', :record => :none) do
            @p.history(:channel => @channel, :count => 10, :http_sync => false, :callback => @msg_callback)
          end
        end
      end

      context "when subscribe is made" do

        context "on the initial subscribe" do
          it 'should provide the auth key in the url' do

            mock(@p).verify_operation('subscribe', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                    :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                    :origin => @origin, :operation => "subscribe", :params => {:uuid => "myuuid", :auth => nil}, :timetoken => nil,
                                                    :error_callback => @err_callback, :channel => @channel, :http_sync => false, :callback => @msg_callback})

            VCR.use_cassette('pam8', :record => :none) do
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)
            end
          end
        end


        context "on the initial and subsequent subscribe" do
          it 'should provide the auth key in the url' do

            mock(@p).verify_operation('subscribe', {:ssl => nil, :cipher_key => nil, :publish_key => "pub-c-e72b633d-bb2f-42ba-8e98-69a9d3f7bdaa",
                                                    :subscribe_key => "sub-c-8e798456-4520-11e3-9b46-02ee2ddab7fe", :secret_key => "sec-c-ZjFjZmRhODMtM2E5Yi00N2ViLWJjYTktMjk2NmExOTQyMmYz",
                                                    :origin => @origin, :operation => "subscribe", :params => {:uuid => "myuuid", :auth => nil}, :timetoken => nil,
                                                    :error_callback => @err_callback, :channel => @channel, :http_sync => false, :callback => @msg_callback}).times(2)

            VCR.use_cassette('pam7', :record => :none) do
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)
              @p.subscribe(:channel => @channel, :http_sync => false, :callback => @msg_callback)


            end
          end
        end
      end
    end
  end

  describe "audit" do
    context "required parameters" do

      context "when the publish key is missing" do
        it "should raise an error" do
          @p = Pubnub.new(:uuid => "myuuid", :subscribe_key => @subscribe_key, :secret_key => @secret_key, :error_callback => @err_callback)
          lambda { @p.audit(:http_sync => true) }.should raise_error(ArgumentError)
        end
      end

      context "when the secret key is missing" do
        it "should raise an error" do
          @p = Pubnub.new(:uuid => "myuuid", :subscribe_key => @subscribe_key, :publish_key => @publish_key, :error_callback => @err_callback)
          lambda { @p.audit(:publish_key => @publish_key, :http_sync => true) }.should raise_error(ArgumentError)
        end
      end


      context "when only the subscribe key is missing" do
        it "should raise an error" do
          @p = Pubnub.new(:uuid => "myuuid", :publish_key => @publish_key, :secret_key => @secret_key, :error_callback => @err_callback)
          lambda { @p.audit(:secret_key => @secret_key, :http_sync => true) }.should raise_error(ArgumentError)
        end
      end

      context "when only the auth key is given with no channel" do
        it "should raise an error" do
          @p = Pubnub.new(:uuid => "myuuid", :publish_key => @publish_key, :subscribe_key => @subscribe_key, :secret_key => @secret_key, :error_callback => @err_callback)
          @p.auth_key = "foo"
          lambda { @p.audit(:secret_key => @secret_key, :http_sync => true) }.should raise_error(ArgumentError)
        end
      end

      context "when the required parameters are given" do
        it "should require secret, pub, and sub keys" do
          @p = Pubnub.new(:uuid => "myuuid", :publish_key => @publish_key, :subscribe_key => @subscribe_key, :secret_key => @secret_key, :error_callback => @err_callback)
          lambda { @p.audit(:http_sync => true) }.should_not raise_error(ArgumentError)
        end
      end



    end

    describe "integration" do

      before do
        any_instance_of(Pubnub::Request) do |request|
          stub(request).current_time { 123456 }
        end
      end

      context "via http" do
        before do
          @p = Pubnub.new(:logger => @logger, :origin => @origin, :uuid => "myuuid", :publish_key => @publish_key, :subscribe_key => @subscribe_key, :secret_key => @secret_key, :error_callback => @err_callback)
        end

        context "synchronously" do
          context "via return" do
            context "audit" do

              context "subkey level" do
                it "should display current stats" do
                  VCR.use_cassette('pam10', :record => :none) do
                    response = @p.audit(:http_sync => true)

                    response.is_error.should be_false
                    response.response["payload"]["channels"].should be_empty
                    response.response["payload"]["level"].should == 'subkey'
                  end
                end
              end

              context "channel level" do
                it "should display current stats" do
                  VCR.use_cassette('pam11', :record => :none) do
                    response = @p.audit(:http_sync => true, :channel => @channel)

                    response.is_error.should be_false
                    response.response["payload"]["channels"].should be_empty
                    response.response["payload"]["level"].should == 'channel'

                  end

                end
              end

              context "channel and user level" do

                it "should display current stats" do
                  VCR.use_cassette('pam12', :record => :none) do
                    @p.auth_key = @auth_key
                    response = @p.audit(:http_sync => true, :channel => @channel)

                    response.is_error.should be_false
                    response.response["payload"]["channel"].should == "mychannel"
                    response.response["payload"]["level"].should == 'user'

                  end

                end

              end


            end

          end
        end

      end
    end

  end


end
