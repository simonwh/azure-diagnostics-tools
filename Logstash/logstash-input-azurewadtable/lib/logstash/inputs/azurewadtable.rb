# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "time"
require "azure"

class LogStash::Inputs::AzureWADTable < LogStash::Inputs::Base
  class Interrupted < StandardError; end

  config_name "azurewadtable"
  milestone 1

  config :account_name, :validate => :string
  config :access_key, :validate => :string
  config :table_name, :validate => :string
  config :entity_count_to_process, :validate => :string, :default => 100
  config :collection_start_time_utc, :validate => :string, :default => Time.now.utc.iso8601
  config :etw_pretty_print, :validate => :boolean, :default => false
  config :idle_delay_seconds, :validate => :number, :default => 15
  config :endpoint, :validate => :string, :default => "core.windows.net"

  # Default 1 minute delay to ensure all data is published to the table before querying.
  # See issue #23 for more: https://github.com/Azure/azure-diagnostics-tools/issues/23
  config :data_latency_minutes, :validate => :number, :default => 1

  TICKS_SINCE_EPOCH = Time.utc(0001, 01, 01).to_i * 10000000

  def initialize(*args)
    super(*args)
  end # initialize

  public
  def register
    Azure.configure do |config|
      config.storage_account_name = @account_name
      config.storage_access_key = @access_key
      config.storage_table_host = "https://#{@account_name}.table.#{@endpoint}"
     end
    @azure_table_service = Azure::Table::TableService.new
    @last_timestamp = @collection_start_time_utc
    @idle_delay = @idle_delay_seconds
    @continuation_token = nil
  end # register

  public
  def run(output_queue)
    while !stop?
      @logger.debug("Starting process method @" + Time.now.to_s);
      process(output_queue)
      @logger.debug("Starting delay of: " + @idle_delay_seconds.to_s + " seconds @" + Time.now.to_s);
      sleep @idle_delay
    end # while
  end # run

  public
  def teardown
  end

  def build_latent_query
    @logger.debug("from #{@last_timestamp} to #{@until_timestamp}")
    query_filter = "(PartitionKey gt '#{partitionkey_from_datetime(@last_timestamp)}' and PartitionKey lt '#{partitionkey_from_datetime(@until_timestamp)}')"
    for i in 0..99
      query_filter << " or (PartitionKey gt '#{i.to_s.rjust(19, '0')}___#{partitionkey_from_datetime(@last_timestamp)}' and PartitionKey lt '#{i.to_s.rjust(19, '0')}___#{partitionkey_from_datetime(@until_timestamp)}')"
    end # for block
    query_filter = query_filter.gsub('"','')
    query_filter
  end

  def build_zero_latency_query
    @logger.debug("from #{@last_timestamp} to most recent data")
    # query data using start_from_time
    query_filter = "(PartitionKey gt '#{partitionkey_from_datetime(@last_timestamp)}')"
    for i in 0..99
      query_filter << " or (PartitionKey gt '#{i.to_s.rjust(19, '0')}___#{partitionkey_from_datetime(@last_timestamp)}' and PartitionKey lt '#{i.to_s.rjust(19, '0')}___9999999999999999999')"
    end # for block
    query_filter = query_filter.gsub('"','')
    query_filter
  end

  def process(output_queue)
    if @data_latency_minutes > 0
      @until_timestamp = (Time.now - (60 * @data_latency_minutes)).iso8601 unless @continuation_token
      query_filter = build_latent_query
    else
      query_filter = build_zero_latency_query
    end
    @logger.debug("Query filter: " + query_filter)
    query = { :top => @entity_count_to_process, :filter => query_filter, :continuation_token => @continuation_token }
    result = @azure_table_service.query_entities(@table_name, query)
    @continuation_token = result.continuation_token

    if result and result.length > 0
      last_good_timestamp = nil
      result.each do |entity|
        event = LogStash::Event.new(entity.properties)
        event["type"] = @table_name

        # Help pretty print etw files
        if (@etw_pretty_print && !event["EventMessage"].nil? && !event["Message"].nil?)
          @logger.debug("event: " + event.to_s)
          eventMessage = event["EventMessage"].to_s
          message = event["Message"].to_s
          @logger.debug("EventMessage: " + eventMessage)
          @logger.debug("Message: " + message)
          if (eventMessage.include? "%")
            @logger.debug("starting pretty print")
            toReplace = eventMessage.scan(/%\d+/)
            payload = message.scan(/(?<!\\S)([a-zA-Z]+)=(\"[^\"]*\")(?!\\S)/)
            # Split up the format string to seperate all of the numbers
            toReplace.each do |key|
              @logger.debug("Replacing key: " + key.to_s)
              index = key.scan(/\d+/).join.to_i
              newValue = payload[index - 1][1]
              @logger.debug("New Value: " + newValue)
              eventMessage[key] = newValue
            end # do block
            event["EventMessage"] = eventMessage
            @logger.debug("pretty print end. result: " + event["EventMessage"].to_s)
          end
        end
        decorate(event)
        if event['PreciseTimeStamp'].is_a?(Time)
          event['PreciseTimeStamp']=LogStash::Timestamp.new(event['PreciseTimeStamp'])
        end
        output_queue << event
        if (!event["TIMESTAMP"].nil?)
          last_good_timestamp = event["TIMESTAMP"]
        end
      end # each block
      @idle_delay = 0
      if (!last_good_timestamp.nil?)
        @last_timestamp = last_good_timestamp.iso8601 unless @continuation_token
      end
    else
      @logger.debug("No new results found.")
      @idle_delay = @idle_delay_seconds
    end # if block

  rescue => e
    @logger.error("Oh My, An error occurred.", :exception => e)
    raise
  end # process

  # Windows Azure Diagnostic's algorithm for determining the partition key based on time is as follows:
  # 1. Take time in UTC without seconds.
  # 2. Convert it into .net ticks
  # 3. add a '0' prefix.
  def partitionkey_from_datetime(time_string)
    collection_time = Time.parse(time_string)
    if collection_time
      @logger.debug("collection time parsed successfully #{collection_time}")
    else
      raise(ArgumentError, "Could not parse the time_string")
    end # if else block

    collection_time -= collection_time.sec
    ticks = to_ticks(collection_time)
    "0#{ticks}"
  end # partitionkey_from_datetime

  # Convert time to ticks
  def to_ticks(time_to_convert)
    @logger.debug("Converting time to ticks")
    time_to_convert.to_i * 10000000 - TICKS_SINCE_EPOCH
  end # to_ticks

end # LogStash::Inputs::AzureWADTable
