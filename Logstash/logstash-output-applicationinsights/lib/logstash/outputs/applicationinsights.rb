# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "application_insights"

include ApplicationInsights
include ApplicationInsights::Channel

class LogStash::Outputs::ApplicationInsights < LogStash::Outputs::Base
  config_name "applicationinsights"

  config :ikey, :validate => :string, :required => true
  config :ai_type, :validate => :string, :required => true
  config :dev_mode, :validate => :boolean, :required => false, :default => false
  config :ai_message_field, :validate => :string, :required => false, :default => nil
  config :ai_properties_field, :validate => :string, :required => false, :default => nil
  config :ai_severity_level_field, :validate => :string, :required => false, :default => nil
  config :ai_severity_level_mapping, :validate => :hash, :required => false, :default => nil
  config :ai_metrics_names, :validate => :array, :required => false, :default => nil
  config :ai_event_name, :validate => :string, :required => false, :default => nil
  
  public
  def register
     create_client
  end # def register

  public
  def multi_receive(events)
    events.each do |event|
      begin
        ai_properties = get_ai_properties(event)
        if @ai_type == "trace"
          ai_message = get_field(event, @ai_message_field)
          ai_severity = get_ai_severity(event)
          @client.track_trace(ai_message, ai_severity, { :properties => ai_properties })
        elsif @ai_type == "metric"
          if !@ai_metrics_names.nil? && @ai_metrics_names.any?
            @ai_metrics_names.each do |metric_name|
              metric_value = get_field(event, metric_name)
              if metric_value.nil?
                @logger.warn("#{@metric_name} specified in ai_metrics_names not found in event data.")
              else
                @client.track_metric(metric_name, metric_value.to_f, { :properties => ai_properties })
              end  # if
            end # do
          end # if ai_metric_fields
        elsif @ai_type == "event"
          @client.track_event(@ai_event_name, { :properties => ai_properties }) if !@ai_event_name.nil?
        end # if ai_type

        @client.flush if @dev_mode

      rescue => e
        @logger.error("Error occurred sending data to AI.", :exception => e)
      end # begin
    end # do 
  end # def multi_receive
  
  def close
    @client.flush
  end # def close

  def create_client
    telemetry_context = TelemetryContext.new
    async_queue = AsynchronousQueue.new(AsynchronousSender.new)
    telemetry_channel = TelemetryChannel.new(telemetry_context, async_queue)
    @client = TelemetryClient.new(@ikey, telemetry_channel)
  end # def create_client
  
  def get_field(event, field_name)
    return nil if field_name.nil?
    
    field = event[field_name] # Extracts specified field value as the AI Message.
    @logger.warn("#{field_name} not found in event data.") if field.nil?
    event.remove(field_name) unless field.nil?  # Removes the duplicated AI field.
    field
  end # def get_ai_message
  
  def get_ai_properties(event)
    ai_properties = event.to_hash.fetch(@ai_properties_field, nil)
    if !@ai_properties_field.nil? && ai_properties.nil?
      @logger.warn("#{@ai_properties_field} specified in ai_properties_field not found in event data. Will use all fields in event as AI properties.")
    end # if

    ai_properties || event.to_hash
  end # def get_ai_properties
  
  def get_ai_severity(event)
    return nil if @ai_severity_level_field.nil? 

    severity_value = event[@ai_severity_level_field]

    if !@ai_severity_level_mapping.nil? && @ai_severity_level_mapping.any?
      ai_severity_level = @ai_severity_level_mapping.fetch(severity_value, nil)
    else
      ai_severity_level = severity_value
    end # unless

    if ai_severity_level.nil?
      @logger.warn("Cannot map value '#{severity_value}' from '#{@ai_severity_level_field}' to AI severity level. Will use default value.")
    else
      event.remove(@ai_severity_level_field)  # Removes the duplicated severity field.
    end # if
    
    ai_severity_level
  end # def get_ai_severity

end # LogStash::Outputs::ApplicationInsights