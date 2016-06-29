# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "azure"
require "base64"
require "securerandom"

# Reads events from Azure Blobs
class LogStash::Inputs::Azureblob < LogStash::Inputs::Base
  # Define the plugin name
  config_name "azureblob"

  # Define the milestone
  # Ref: https://github.com/elastic/logstash/blob/1.4/docs/plugin-milestones.md
  milestone 1

  # Codec
  # *Possible values available at https://www.elastic.co/guide/en/logstash/current/codec-plugins.html
  # *Most used: json_lines, line, etc.
  default :codec, "json_lines"
  
  # storage_account_name
  # *Define the Azure Storage Account Name
  config :storage_account_name, :validate => :string

  # storage_access_key
  # *Define the Azure Storage Access Key (available through the portal)
  config :storage_access_key, :validate => :string

  # container
  # *Define the container to watch
  config :container, :validate => :string

  # sleep_time
  # *Define the sleep_time between scanning for new data
  config :sleep_time, :validate => :number, :default => 10
  
  # [New]
  # blob_type
  # *Define the type of blob
  # *Possible values: [iis|normal]
  config :blob_type, :validate => :string, :default => "normal"
  
  # [New]
  # path_pattern
  # *Define the path pattern in the container in order to not take everything
  # *Can also be an array.
  config :path_pattern, :validate => :array, :required => true

  # [New]
  # since_db
  # *Define the Azure Storage Table where we can drop information about the the blob we're collecting. 
  # *Important! The since_db will be on the container we're watching.
  # *By default, we don't use the since_db
  config :since_db, :validate => :string

  # [New]
  # start_from
  # *Define which blob we want to watch using start_from. If any file with last_modification is before that, we consider it obsolete. Any file having a newer "last_modification" >= will be taken.
  config :start_from, :validate => :string

  # Initialize the plugin
  def initialize(*args)
    super(*args)
  end # def initialize
  
  public
  def register
    Azure.configure do |config|
      config.storage_account_name = @storage_account_name
      config.storage_access_key = @storage_access_key
    end
    @azure_blob = Azure::Blob::BlobService.new
    
    if (@since_db)
      @azure_table = Azure::Table::TableService.new
      init_wad_table
    end
  end # def register
  
  # Initialize the WAD Table if we have a since_db defined.
  def init_wad_table
    if (@since_db)
      begin
        @azure_table.create_table(@since_db) # Be sure that the table name is properly named.
      rescue
        # table already exists
      end
    end
  end # def init_wad_table
  
  # List the blob names in the container. If we have any path pattern defined, it will filter 
  # the blob names from the list. The status of the blobs will be persisted in the WAD table.
  #
  # Returns the list of blob_names to read from.
  def list_blobs
    blobs = Hash.new
    
    loop do
      continuation_token = NIL
      # Each blob contains their respective properties
      # * :last_modified
      # * :etag
      # * :lease_status
      # * :lease_state
      # * :content_length
      # * :content_type
      # * :content_encoding
      # * :content_language
      # * :content_md5
      # * :cache_control
      # * :blob_type
      entries = @azure_blob.list_blobs(@container, { :timeout => 10, :marker => continuation_token})
      entries.each do |entry|
        # Todo, use regex pattern check instead of hard check.
        if :path_pattern 
          if :path_pattern === entry.name
            blobs[entry.name] = entry
          end
        else
          blobs[entry.name] = entry
        end
      end
      continuation_token = entries.continuation_token
      break if continuation_token.empty?
    end

    return blobs
  end # def list_blobs

  # Acquire the lock on the blob. Default duration is 60 seconds with a timeout of 10 seconds.
  # *blob_name: Blob name to threat
  # Returns true if the aquiring works
  def acquire_lock(blob_name)
    @azure_blob.create_page_blob(@container, blob_name, 512)
    @azure_blob.acquire_lease(@container, blob_name,{:duration=>60, :timeout=>10, :proposed_lease_id=>SecureRandom.uuid})

    return true
    
    # Shutdown signal for graceful shutdown in LogStash
    rescue LogStash::ShutdownSignal => e
      raise e
    rescue => e
      @logger.error("Caught exception while locking", :exception => e)
    return false
  end # def acquire_lock
  
  # Do the official lock on the blob
  # *blob_names: Array of blob names to threat
  def lock_blob(blobs)
    # Take all the blobs without a lock file.
    real_blobs = blobs.select { |name, v| !name.end_with?(".lock") }
  
    # Return the first one not marked as locked + lock it.
    real_blobs.each do |blob_name, blob|
      if !blobs.keys.include?(blob_name + ".lock")      
        if acquire_lock(blob_name + ".lock")
          return blob
        end
      end
    end

    return NIL
  end # def lock_blob

  def list_sinceDbContainerEntities
    entities = Set.new
    
    loop do
      continuation_token = NIL

      entries = @azure_table.query_entities(@since_db, { :filter => "PartitionKey eq '#{container}'", :continuation_token => continuation_token}) 
      entries.each do |entry|
          entities << entry
      end
      continuation_token = entries.continuation_token
      break if continuation_token.empty?
    end

    return entities
  end # def list_sinceDbContainerEntities

  # Process the plugin ans start watching.
  def process(output_queue)
    blobs = list_blobs

    # use the azure table in order to set the :start_range and :end_range
    # When we do that, we shouldn't use the lock strategy, since we know where we are at. It would still be interesting in a multi-thread
    # environment.
    if (@since_db)
      ## TODO implement the start from.
      #if (@start_from)
      # blob_info.properties[:last_modified]

      existing_entities = list_sinceDbContainerEntities # @azure_table.query_entities(@since_db, { :filter => "PartitionKey eq '#{container}'"}) # continuation_token...

      blobs.each do |blob_name, blob_info|
        blob_name_encoded = Base64.strict_encode64(blob_info.name)
        entityIndex = existing_entities.find_index {|entity| entity.properties["RowKey"] == keyBase64 }

        # Entity row 
        # *PartitionKey => Container name
        # *RowKey       => Blob name
        # *ByteOffset   => Define where we need to start reading
        # *ETag         => Define the last ETag
        entity = { 
          "PartitionKey" => @container, 
          "RowKey" => blob_name_encoded, 
          "ByteOffset" => 0, 
          "ETag" => NIL
        }

        if (entityIndex)
          # exists in table
          foundEntity = existing_entities[entityIndex];
          entity["ByteOffset"] = foundEntity.properties["ByteOffset"]
          entity["ETag"] = foundEntity.properties["ETag"] 
        end

        if (entity["ETag"] === blob_info.properties[:etag])
          # nothing to do...
          # puts "Blob already up to date"
        else
          blob, content = @azure_blob.get_blob(@container,  blob_info.name, { :start_range => entity["ByteOffset"], :end_range =>  blob_info.properties[:content_length] })

          @codec.decode(content) do |event|
            output_queue << event
          end 

          # Update the entity with the latest informations we used while processing the blob. If we have a crash, 
          # we will re-process the last batch.
          entity["ByteOffset"] = blob_info.properties[:content_length]
          entity["ETag"] = blob_info.properties[:etag]
          @azure_table.insert_or_merge_entity(@since_db, entity)
        end
      end

      return true
    else
      # Process the ones not yet processed. (The newly locked blob)
      blob_info = lock_blob(blobs)
    
      # Do what we were doing before
      return if !blob_info.name
        blob, content = @azure_blob.get_blob(@container, blob_info.name)
        @codec.decode(content) do |event|
          output_queue << event
      end
    end
    
    # Shutdown signal for graceful shutdown in LogStash
    rescue LogStash::ShutdownSignal => e
      raise e
    rescue => e
      @logger.error("Oh My, An error occurred.", :exception => e)
  end # def process
  
  # Run the plugin (Called directly by LogStash)
  public
  def run(output_queue)
    # Infinite processing loop.
    while !stop?
      process(output_queue)
      
      # todo maybe we should wait using the sleep_time ?
    end # loop
  end # def run
 
  public
  def teardown
    # Nothing to do.
  end # def teardown
end # class LogStash::Inputs::Azuretopic