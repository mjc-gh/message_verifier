require 'logger'
require 'active_support'
require 'active_support/key_generator'
require 'active_support/message_encryptor'
require 'json'

include ActiveSupport

key_base = 'helloworld'
key_gen  = KeyGenerator.new(key_base, iterations: 1000, hash_digest_class: OpenSSL::Digest::SHA1)

salt      = key_gen.generate_key('test salt', MessageEncryptor.key_len('aes-256-cbc'))
sign_salt = key_gen.generate_key('test signed salt')

verifier  = MessageVerifier.new(key_base, serializer: JSON)
encryptor = MessageEncryptor.new(salt, sign_salt, cipher: 'aes-256-cbc', serializer: JSON)

message = { key: 'value' }

puts verifier.generate(message)
puts encryptor.encrypt_and_sign(message)
