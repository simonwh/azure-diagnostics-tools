# Logstash output plugin for Application Insights 

## Summary


## Installation
You can install this plugin using the Logstash "plugin" or "logstash-plugin" (for newer versions of Logstash) command:
```sh
logstash-plugin install logstash-output-applicationinsights
```
For more information, see Logstash reference [Working with plugins](https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html).

## Configuration
### Required Parameters
__*ikey*__

The Application Insights Instrumentation key.

__*ai_type*__

The type of Application Insights event: "trace", "metric" and "event" are supported

### Optional Parameters
__*ai_message_field*__

Specifies the name of the event field to be used as the Message field of the Application Insights trace. If not specified, Message in Application Insights will be "Null".

__*ai_properties_field*__

Specifies the name of the event field to be used as the Properties field of the Application Insights trace. The type of the field needs to be Hash. If not specified, all fields in event will be used.

__*ai_severity_level_field*__

Specifies the name of the event field to be used as the Severity level of the Application Insights trace. If not specified, all traces will be "Informational".

__*ai_severity_level_mapping*__

Specifies how to map the values read from *ai_severity_level_field* to Application Insights severity level. This is a hash containing the possible values from event as keys and corresponding Application Insights Severity Level constants as values.

See example below for how to map [Azure diagnostics log level values](https://msdn.microsoft.com/en-us/library/azure/microsoft.windowsazure.diagnostics.loglevel.aspx) to [Application Insights severity values](https://github.com/Microsoft/ApplicationInsights-Ruby/blob/master/lib/application_insights/channel/contracts/severity_level.rb).

__*ai_metrics_names*__

Specifies the names of the event fields to be used as metrics name; the value of each field specified will be reported as metric value. If not specified, no metric will be reported. 

__*ai_event_name*__

Specifies the name of the event to be reported; If not specified, no event will be reported. 

__*dev_mode*__

If this is set to True, the plugin sends telemetry to Application Insights immediately; otherwise the plugin respects production sending policies defined by other properties.

### Examples
```
output
{
    applicationinsights
    {
        ikey => "00000000-0000-0000-0000-000000000000"
        dev_mode => true
        ai_message_field => "EventMessage"
        ai_properties_field => "EventProperties"
        ai_severity_level_field => "level"
        ai_severity_level_mapping => { 5 => 0 4 => 1 3 => 2 2 => 3 1 => 4 0 => 4 }
    }
}
```

## More information
The source code of this plugin is hosted in GitHub repo [Microsoft Azure Diagnostics with ELK](https://github.com/Azure/azure-diagnostics-tools). We welcome you to provide feedback and/or contribute to the project.

Please also see [Analyze Diagnostics Data with ELK template](https://github.com/Azure/azure-quickstart-templates/tree/master/diagnostics-with-elk) for quick deployment of ELK to Azure.   
