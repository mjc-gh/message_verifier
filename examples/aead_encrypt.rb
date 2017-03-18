require 'active_support'
require 'json'

cipher = 'aes-256-gcm'

key_base = 'helloworld'
key_gen  = ActiveSupport::KeyGenerator.new(key_base, iterations: 1000)

salt      = key_gen.generate_key('test salt')[0, ActiveSupport::MessageEncryptor.key_len(cipher)]
encryptor = ActiveSupport::MessageEncryptor.new(salt, cipher: cipher, serializer: JSON)

message = { key: 'value' }

puts encryptor.encrypt_and_sign(message)
