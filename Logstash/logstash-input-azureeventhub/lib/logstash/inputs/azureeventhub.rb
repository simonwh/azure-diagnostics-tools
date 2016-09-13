# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "securerandom"
require "open-uri"
require "thread"

require Dir[ File.dirname(__FILE__) + "/../../*_jars.rb" ].first

# Reads events from Azure event-hub
class LogStash::Inputs::Azureeventhub < LogStash::Inputs::Base

  config_name "azureeventhub"
  milestone 1

  default :codec, "json"
  
  config :key, :validate => :string
  config :username, :validate => :string
  config :namespace, :validate => :string
  config :domain, :validate => :string, :default => "servicebus.windows.net"
  config :port, :validate => :number, :default => 5671
  config :receive_credits, :validate => :number, :default => 1000
  
  config :eventhub, :validate => :string
  config :partitions, :validate => :number
  config :consumer_group, :validate => :string, :default => "$default"
  
  config :time_since_epoch_millis, :validate => :number, :default => Time.now.utc.to_i * 1000
  config :thread_wait_sec, :validate => :number, :default => 5
  
  
  def initialize(*args)
    super(*args)
  end # def initialize

  public
  def register
  end # def register

  def get_pay_load(message)
    return nil if not message
    message.getPayload().each do |section|
      if section.java_kind_of? org::apache::qpid::amqp_1_0::type::messaging::Data or section.java_kind_of? org::apache::qpid::amqp_1_0::type::messaging::AmqpValue
        return section.getValue().to_s.gsub("\\x5c", "\\")
      end
    end
    return nil
  end
  
  def process(output_queue, receiver, partition)
    while !stop?
      begin
        msg = receiver.receive(10)
        if msg
          codec.decode(get_pay_load(msg)) do |event|
            decorate(event)
            output_queue << event
          end
          receiver.acknowledge(msg)
        else
          @logger.debug("  " + partition.to_s.rjust(2,"0") + " --- " + "No message")
          sleep(@thread_wait_sec)
        end
      rescue LogStash::ShutdownSignal => e
        raise e
      rescue org::apache::qpid::amqp_1_0::client::ConnectionErrorException => e
        raise e
      rescue => e
        @logger.error("  " + partition.to_s.rjust(2,"0") + " --- " + "Oh My, An error occurred.", :exception => e)
      end
    end # process
  end # process
  
  def process_partition(output_queue, partition)
    while !stop?
      begin
        filter = SelectorFilter.new "amqp.annotation.x-opt-enqueuedtimeutc > '" + @time_since_epoch_millis.to_s + "'"
        filters = { org::apache::qpid::amqp_1_0::type::Symbol.valueOf("apache.org:selector-filter:string") => filter }

        host = @namespace + "." + @domain
        connection = org::apache::qpid::amqp_1_0::client::Connection.new(host, @port, @username, @key, host, true)
        connection.getEndpoint().getDescribedTypeRegistry().register(filter.java_class, WriterFactory.new)
        receiveSession = connection.createSession()
        receiver = receiveSession.createReceiver(@eventhub + "/ConsumerGroups/" + @consumer_group + "/Partitions/" + partition.to_s, org::apache::qpid::amqp_1_0::client::AcknowledgeMode::ALO, "eventhubs-receiver-link-" + partition.to_s, false, filters, nil)
        receiver.setCredit(org::apache::qpid::amqp_1_0::type::UnsignedInteger.valueOf(@receive_credits), true)
        process(output_queue,receiver,partition)
      rescue org::apache::qpid::amqp_1_0::client::ConnectionErrorException => e
        @logger.debug("  " + partition.to_s.rjust(2,"0") + " --- " + "resetting connection")
        @time_since_epoch_millis = Time.now.utc.to_i * 1000
      end
    end
  rescue LogStash::ShutdownSignal => e
    receiver.close()
    raise e
  rescue => e
    @logger.error("  " + partition.to_s.rjust(2,"0") + " --- Oh My, An error occurred.", :exception => e)
  end # process

  public
  def run(output_queue)
    threads = []
    (0..(@partitions-1)).each do |p_id|
      threads << Thread.new { process_partition(output_queue, p_id) }
    end
    threads.each { |thr| thr.join }
  end # def run

  public
  def teardown
  end # def teardown
end # class LogStash::Inputs::Azureeventhub


class SelectorFilter
  include org::apache::qpid::amqp_1_0::type::messaging::Filter

  def initialize(value)
    @value = value
  end

  def getValue
    return @value
  end

  def toString
    return @value
  end
end

class SelectorFilterWriter < org::apache::qpid::amqp_1_0::codec::AbstractDescribedTypeWriter
  def initialize(registry)
    super(registry)
  end
  
  def onSetValue(value)
    @value = value
  end
  
  def clear
    @value = nil
  end
  
  def getDescriptor
    return org::apache::qpid::amqp_1_0::type::UnsignedLong.valueOf(83483426826);
  end
  
  def createDescribedWriter
    return getRegistry().getValueWriter(@value.getValue());
  end
end

class WriterFactory
  include org::apache::qpid::amqp_1_0::codec::ValueWriter::Factory

  def newInstance(registry)
    return SelectorFilterWriter.new registry
  end
end
