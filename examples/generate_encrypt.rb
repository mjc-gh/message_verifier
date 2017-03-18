require 'active_support'
require 'json'

include ActiveSupport

key_base = 'helloworld'
key_gen  = KeyGenerator.new(key_base, iterations: 1000)

salt      = key_gen.generate_key('test salt')[0, MessageEncryptor.key_len]
sign_salt = key_gen.generate_key('test signed salt')

verifier  = MessageVerifier.new(key_base, serializer: JSON)
encryptor = MessageEncryptor.new(salt, sign_salt, serializer: JSON)

message = { key: 'value' }

puts verifier.generate(message)
puts encryptor.encrypt_and_sign(message)
