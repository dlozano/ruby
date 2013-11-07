require 'pubnub'

class Thrash

  THRASHERS = 3
  PIPELINE = 10000

  def initialize

    @progress = THRASHERS * PIPELINE
    @thrashers = []

    THRASHERS.times do
      @thrashers.push(new_pubnub)
    end

  end

  def response_tracker(envelope)
    @progress -= 1
    puts "p - #{@progress}"
  end

  def fire
    puts "Ready..."

    @thrashers.each_with_index do |thrash, i|
      Thread.new{
      puts "aim..."

      PIPELINE.times do | x |
        puts(x)
        thrash.publish(:http_sync => false, :message => "#{i} / #{x} : fire!", :channel => "unleash", :callback => method(:response_tracker))
      end

      }
    end


    while @progress > 1
      puts("Waiting for responses. At: #{@progress}")
      sleep 1
    end

  end

  def new_pubnub
    p = Pubnub.new(
        :ssl => false,
        :subscribe_key => 'demo',
        :publish_key => 'demo',
        :error_callback => lambda { |e|
          puts "ERROR! #{e.inspect}"
          puts this.inspect
        }
    )
  end

  def self.fire
    fire
  end

end

puts Time.now
t = Thrash.new.fire

puts Time.now
