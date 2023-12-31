# frozen_string_literal: true

require_relative "lib/omniauth/myminifactory/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-myminifactory"
  spec.version = Omniauth::Myminifactory::VERSION
  spec.authors = ["Philip Solobay"]
  spec.email = ["maximus242@gmail.com"]

  spec.summary = "Omniauth for MyMiniFactory"
  spec.description = "Provides Omniauth Functionality for MyMiniFactory"
  spec.homepage = "https://www.github.com"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["allowed_push_host"] = "https://www.rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://www.github.com"
  spec.metadata["changelog_uri"] = "https://www.github.com"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor Gemfile])
    end
  end

  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"
  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.7'
  spec.add_development_dependency 'webmock', '~> 3.19', '>= 3.19.1'
  spec.add_development_dependency 'rspec'
  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
