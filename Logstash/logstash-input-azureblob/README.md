# Logstash input plugin for Azure Storage Blobs

## Summary
This plugin reads and parses data from Azure Storage Blobs.

## Installation
You can install this plugin using the Logstash "plugin" or "logstash-plugin" (for newer versions of Logstash) command:
```sh
logstash-plugin install logstash-input-azureblob
```
For more information, see Logstash reference [Working with plugins](https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html).

## Configuration
### Required Parameters
__*storage_account_name*__

The storage account name.

__*storage_access_key*__

The access key to the storage account.

__*container*__

The blob container name.

__*codec (optional)*__

The codec used to decode the blob. By default *json_lines* is selected.

__*sleep_time (optional) / Does not seems to be implemented*__

The sleep time before scanning for new data. By default *10* seconds.

__*since_db (optional)*__

Use Azure Table to keep track of what have been done. This define the table name that will be used.

No default value, if a value is defined, than it will create the *since_db*.

__*path_pattern (optional)*__

**Not implemented**

Array of Ruby RegEx defining the path pattern to watch in the blob container. Path are defined by the blob name (i.e.: /path/to/blob.log).

No default value.

__*blob_type? (optional)*__

**Not implemented**

Possible values are *normal* or *iis*. Since the WebApp in Azure use the blob to store the IIS Logs, the structure is well defined per hours. Once it was tracked and we are not anymore in that hour, we should not scan for this anymore.

Default value is *normal*.

__*start_from (optional)*__

**Not implemented**

A string that define when to start from. The date format for the string is as following : Fri, 10 Jun 2016 06:59:57 GMT

### Examples
```
input
{
    azureblob
    {
        storage_account_name => "mystorageaccount"
        storage_access_key => "VGhpcyBpcyBhIGZha2Uga2V5Lg=="
        container => "mycontainer"
    }
}
```

## More information
The source code of this plugin is hosted in GitHub repo [Microsoft Azure Diagnostics with ELK](https://github.com/Azure/azure-diagnostics-tools). We welcome you to provide feedback and/or contribute to the project.