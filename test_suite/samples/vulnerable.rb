#!/usr/bin/env ruby

require 'active_record'
require 'yaml'
require 'json'
require 'open3'
require 'net/http'
require 'digest'

# SQL Injection vulnerabilities
class VulnerableUser < ActiveRecord::Base
  def self.find_by_unsafe_query(user_input)
    # CWE-89: SQL Injection
    where("name = '#{user_input}'")
  end
  
  def self.dangerous_sql(id)
    # Raw SQL injection
    connection.execute("SELECT * FROM users WHERE id = #{id}")
  end
  
  def self.find_by_sql_injection(name)
    # find_by_sql injection
    find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
  end
end

# Command Injection vulnerabilities
def vulnerable_system_calls(user_input)
  # CWE-78: Command Injection
  system("echo #{user_input}")
  `ls #{user_input}`
  exec("cat #{user_input}")
  spawn("grep #{user_input} /etc/passwd")
  
  # Using Open3
  Open3.capture3("ping #{user_input}")
end

# Code Injection vulnerabilities
def vulnerable_eval(user_code)
  # CWE-94: Code Injection
  eval(user_code)
  instance_eval(user_code)
  class_eval(user_code)
  
  # Dangerous method calls
  Object.const_get(user_code)
  send(user_code)
end

# Insecure Deserialization
def vulnerable_deserialization(data)
  # CWE-502: Insecure Deserialization
  Marshal.load(data)
  YAML.load(data)
  JSON.load(data)
end

# Path Traversal vulnerabilities
def vulnerable_file_operations(filename)
  # CWE-22: Path Traversal
  File.read(filename)
  File.open(filename, 'r')
  IO.read(filename)
  
  # File writing
  File.write(filename, "sensitive data")
end

# Weak Cryptography
def weak_crypto_algorithms(data)
  # CWE-327: Weak cryptographic algorithms
  md5_hash = Digest::MD5.hexdigest(data)
  sha1_hash = Digest::SHA1.hexdigest(data)
  
  return [md5_hash, sha1_hash]
end

# Hardcoded Secrets
class HardcodedSecrets
  # CWE-798: Hardcoded credentials
  PASSWORD = "SuperSecret123!"
  API_KEY = "sk_live_1234567890abcdef"
  DATABASE_URL = "postgresql://user:password@localhost/mydb"
  SECRET_TOKEN = "my_secret_token_2024"
  
  def initialize
    @admin_password = "admin123"
    @encryption_key = "MyEncryptionKey2024"
  end
end

# SSRF vulnerabilities
def vulnerable_http_requests(url)
  # CWE-918: Server-Side Request Forgery
  uri = URI(url)
  Net::HTTP.get(uri)
  
  # Another SSRF
  Net::HTTP.post_form(URI(url), {'data' => 'value'})
end

# Regular Expression DoS
def vulnerable_regex(user_input)
  # ReDoS vulnerability
  regex = /^(a+)+$/
  user_input =~ regex
  
  # Another ReDoS pattern
  /^(a*)*$/.match(user_input)
end

# Mass Assignment vulnerability
class VulnerableModel < ActiveRecord::Base
  # No attr_accessible or strong parameters
  def update_attributes_unsafely(params)
    update_attributes(params) # Mass assignment vulnerability
  end
end

# Cross-Site Scripting (XSS) in ERB templates
def vulnerable_template_rendering(user_input)
  # XSS in template
  erb_template = ERB.new("<%= #{user_input} %>")
  erb_template.result
end

# Insecure Random Number Generation
def weak_random_generation
  # Weak random number generation
  rand(1000000)
  Random.rand(1000000)
  
  # Predictable session tokens
  session_token = rand.to_s
  return session_token
end

# Information Disclosure
def information_disclosure
  # Exposing sensitive information
  puts ENV.to_h
  puts $LOAD_PATH
  
  # Stack trace exposure
  begin
    raise "Error"
  rescue => e
    puts e.backtrace
  end
end

# LDAP Injection
def ldap_injection(username)
  # CWE-90: LDAP Injection
  filter = "(uid=#{username})"
  # LDAP search with unsanitized input
end

# XML External Entity (XXE)
def xxe_vulnerability(xml_data)
  # CWE-611: XXE
  require 'rexml/document'
  doc = REXML::Document.new(xml_data)
end

# Race Condition
class RaceConditionExample
  def initialize
    @counter = 0
  end
  
  def increment_unsafe
    # Race condition - no synchronization
    1000.times do
      Thread.new do
        @counter += 1 # Unsafe concurrent access
      end
    end
  end
end

# Main execution demonstrating vulnerabilities
if __FILE__ == $0
  puts "Demonstrating Ruby vulnerabilities..."
  
  # SQL injection
  VulnerableUser.find_by_unsafe_query("'; DROP TABLE users; --")
  
  # Command injection
  vulnerable_system_calls("; rm -rf /")
  
  # Code injection
  vulnerable_eval("system('whoami')")
  
  # Deserialization
  vulnerable_deserialization(Marshal.dump({:admin => true}))
  
  # Path traversal
  vulnerable_file_operations("../../../etc/passwd")
  
  # Weak crypto
  weak_crypto_algorithms("sensitive data")
  
  # Hardcoded secrets
  secrets = HardcodedSecrets.new
  
  # SSRF
  vulnerable_http_requests("http://internal.service/admin")
  
  # ReDoS
  vulnerable_regex("aaaaaaaaaaaaaaaaaaaaaaaaaaaa!")
  
  # XSS
  vulnerable_template_rendering("alert('XSS')")
  
  # Weak random
  puts weak_random_generation
  
  # Information disclosure
  information_disclosure
  
  # Race condition
  race_example = RaceConditionExample.new
  race_example.increment_unsafe
end