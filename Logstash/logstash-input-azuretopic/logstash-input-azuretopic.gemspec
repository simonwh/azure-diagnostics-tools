Gem::Specification.new do |s|
  s.name          = 'logstash-input-azuretopic'
  s.version       = '0.9.6'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = "This plugin reads messages from Azure Service Bus Topics."
  s.description   = "This gem is a Logstash plugin. It reads messages from Azure Service Bus Topics."
  s.authors       = ["Microsoft Corporation"]
  s.email         = 'azdiag@microsoft.com'
  s.homepage      = "https://github.com/Azure/azure-diagnostics-tools"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '~> 2.0'
  s.add_runtime_dependency 'azure', '~> 0.7.1'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
end
