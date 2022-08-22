Pod::Spec.new do |spec|
  spec.name          = "AWS4"
  spec.version       = "1.0.0"
  spec.summary       = "AWS4 implementation in Swift for usage in MacOS >= 10.15 or iOS >= 13."
  spec.swift_version = '5.5'
  spec.homepage      = "https://github.com/s5zy/AWS4"
  spec.license       = "MIT"
  spec.author        = { "Matthias Reichmann" => "9638531+s5zy@users.noreply.github.com" }

  spec.ios.deployment_target = "13.0"
  spec.osx.deployment_target = "10.15"

  spec.source        = { :git => "https://github.com/s5zy/AWS4.git", :tag => "#{spec.version}" }
  spec.source_files  = "Sources/AWS4/*.swift"
end
