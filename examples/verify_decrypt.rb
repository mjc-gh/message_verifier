require 'logger'
require 'active_support'
require 'active_support/key_generator'
require 'active_support/message_encryptor'
require 'json'

key_base = 'helloworld'
key_gen  = ActiveSupport::KeyGenerator.new(key_base, iterations: 1000, hash_digest_class: OpenSSL::Digest::SHA1)

salt      = key_gen.generate_key('test salt', ActiveSupport::MessageEncryptor.key_len('aes-256-cbc'))
sign_salt = key_gen.generate_key('test signed salt')

verifier  = ActiveSupport::MessageVerifier.new(key_base, serializer: JSON)
encryptor = ActiveSupport::MessageEncryptor.new(salt, sign_salt, cipher: 'aes-256-cbc', serializer: JSON)

msg1, msg2 = *STDIN.read.split("\n")

puts "Verified message: #{verifier.verify(msg1)}"
puts "Decrypted message: #{encryptor.decrypt_and_verify(msg2)}"
