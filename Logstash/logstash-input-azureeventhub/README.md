# Logstash input plugin for data from Event Hubs 

## Summary
This plugin reads data from specified Azure Event Hubs.

## Installation
You can install this plugin using the Logstash "plugin" or "logstash-plugin" (for newer versions of Logstash) command:
```sh
logstash-plugin install logstash-input-azureeventhub
```
For more information, see Logstash reference [Working with plugins](https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html).

## Configuration
### Required Parameters
__*key*__

The shared access key to the target event hub.

__*username*__

The name of the shared access policy.

__*namespace*__

Event Hub namespace.

__*eventhub*__

Event Hub name.

__*partitions*__

Partition count of the target event hub.

### Optional Parameters
__*domain*__

Domain of the target Event Hub. Default value is "servicebus.windows.net".

__*port*__

Port of the target Event Hub. Default value is 5671.

__*receive_credits*__

The credit number to limit the number of messages to receive in a processing cycle. Default value is 1000.

__*consumer_group*__

Name of the consumer group. Default value is "$default".

__*time_since_epoch_millis*__

Specifies the point of time after which the messages are received. Default value is the time when this plugin is initialized:
```ruby
Time.now.utc.to_i * 1000
```
__*thread_wait_sec*__

Specifies the time (in seconds) to wait before another try if no message was received.

### Examples
```
input
{
    azureeventhub
    {
        key => "VGhpcyBpcyBhIGZha2Uga2V5Lg=="
        username => "receivepolicy"
        namespace => "mysbns"
        eventhub => "myeventhub"
        partitions => 4
    }
}
```

## More information
The source code of this plugin is hosted in GitHub repo [Microsoft Azure Diagnostics with ELK](https://github.com/Azure/azure-diagnostics-tools). We welcome you to provide feedback and/or contribute to the project.

Please also see [Analyze Diagnostics Data with ELK template](https://github.com/Azure/azure-quickstart-templates/tree/master/diagnostics-with-elk) for quick deployment of ELK to Azure.   
