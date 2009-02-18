# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{rubycas-client}
  s.version = "2.0.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Matt Zukowski", "Matt Walker"]
  s.date = %q{2009-02-17}
  s.description = %q{Client library for the Central Authentication Service (CAS) protocol.}
  s.email = %q{matt at roughest dot net}
  s.extra_rdoc_files = ["CHANGELOG.txt", "History.txt", "LICENSE.txt", "Manifest.txt", "README.txt"]
  s.files = ["CHANGELOG.txt", "History.txt", "LICENSE.txt", "Manifest.txt", "README.txt", "Rakefile", "init.rb", "lib/casclient.rb", "lib/casclient/client.rb", "lib/casclient/rest_client.rb", "lib/casclient/frameworks/rails/cas_proxy_callback_controller.rb", "lib/casclient/frameworks/rails/filter.rb", "lib/casclient/frameworks/merb/filter.rb", "lib/casclient/responses.rb", "lib/casclient/tickets.rb", "lib/casclient/version.rb", "lib/rubycas-client.rb", "setup.rb"]
  s.has_rdoc = true
  s.homepage = %q{http://rubycas-client.rubyforge.org}
  s.rdoc_options = ["--main", "README.txt"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{rubycas-client}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{Client library for the Central Authentication Service (CAS) protocol.}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>, [">= 0"])
      s.add_development_dependency(%q<hoe>, [">= 1.8.0"])
    else
      s.add_dependency(%q<activesupport>, [">= 0"])
      s.add_dependency(%q<hoe>, [">= 1.8.0"])
    end
  else
    s.add_dependency(%q<activesupport>, [">= 0"])
    s.add_dependency(%q<hoe>, [">= 1.8.0"])
  end
end
