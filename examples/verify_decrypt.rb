require 'active_support'
require 'json'

key_base = 'helloworld'
key_gen  = ActiveSupport::KeyGenerator.new(key_base, iterations: 1000)

salt      = key_gen.generate_key('test salt')
sign_salt = key_gen.generate_key('test signed salt')

verifier  = ActiveSupport::MessageVerifier.new(key_base, serializer: JSON)
encryptor = ActiveSupport::MessageEncryptor.new(salt, sign_salt, serializer: JSON)

msg1, msg2 = *STDIN.read.split("\n")

puts "Verified message: #{verifier.verify(msg1)}"
puts "Decrypted message: #{encryptor.decrypt_and_verify(msg2)}"
