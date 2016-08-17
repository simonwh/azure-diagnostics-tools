## 2016.08.17
* Added a new configuration parameter for custom endpoint.

## 2016.07.01
* Updated the *README.md*
* Implemented *sleep_time*
* Added *sincedb* parameter (Use Azure table)
* Added *ignore_older* parameter (work as file plugin)
* Added *start_position* parameter (work as file plugin)
* Added *path_prefix* parameter (no wildcard accepted, using Azure blob API)
* Added some logs for debugging

## 2016.05.05
* Made the plugin to respect Logstash shutdown signal.
* Updated the *logstash-core* runtime dependency requirement to '~> 2.0'.
* Updated the *logstash-devutils* development dependency requirement to '>= 0.0.16'

### Not yet completed
* Removed the milestone (deprecated)
