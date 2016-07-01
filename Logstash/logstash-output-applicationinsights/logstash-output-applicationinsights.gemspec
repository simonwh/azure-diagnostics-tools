Gem::Specification.new do |s|
  s.name            = 'logstash-output-applicationinsights'
  s.version         = '0.9.1'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "This plugin sends data to Application Insights."
  s.description     = "This gem is a Logstash plugin. It sends data to Application Insights."
  s.authors         = ["Microsoft Corporation"]
  s.email           = 'azdiag@microsoft.com'
  s.homepage        = "https://github.com/Azure/azure-diagnostics-tools"
  s.require_paths   = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "output" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '~> 2.0'
  s.add_runtime_dependency 'application_insights', '~> 0.5.3'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
end