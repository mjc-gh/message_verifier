# Frozen test protocol shared by the Rust integration tests and Rails version matrix.
require 'logger' # ActiveSupport 7.0 requires Logger to be loaded first.
gem 'json', '< 3' if ENV['ACTIVESUPPORT_VERSION']&.start_with?('7.')
gem 'activesupport', ENV['ACTIVESUPPORT_VERSION'] if ENV['ACTIVESUPPORT_VERSION']
require 'active_support'
require 'active_support/message_verifier'
require 'active_support/message_encryptor'
require 'active_support/key_generator'
require 'json'
require 'time'

def process(request)
  if request.fetch('op') == 'derive'
    generator = ActiveSupport::KeyGenerator.new(
      [request.fetch('key')].pack('H*'),
      iterations: request.fetch('iterations'),
      hash_digest_class: OpenSSL::Digest.const_get(request.fetch('digest'))
    )
    return generator.generate_key([request.fetch('salt')].pack('H*'), request.fetch('length')).unpack1('H*')
  end

  modern = ActiveSupport::Messages::Metadata.respond_to?(:use_message_serializer_for_metadata=)
  ActiveSupport::Messages::Metadata.use_message_serializer_for_metadata = true if modern
  options = {
    serializer: request['raw'] ? ActiveSupport::MessageEncryptor::NullSerializer : JSON,
    digest: request.fetch('digest', 'SHA1')
  }
  if modern
    options[:url_safe] = request.fetch('url_safe', false)
    options[:force_legacy_metadata_serializer] = request.fetch('legacy', false)
  end
  key = [request.fetch('key')].pack('H*')
  codec = if request.fetch('kind') == 'verifier'
    ActiveSupport::MessageVerifier.new(key, **options)
  else
    signing_key = request['signing_key'] && [request['signing_key']].pack('H*')
    ActiveSupport::MessageEncryptor.new(key, signing_key, cipher: request.fetch('cipher'), **options)
  end
  metadata = {}
  metadata[:purpose] = request['purpose'] if request.key?('purpose')
  if request.fetch('op') == 'generate'
    metadata[:expires_at] = Time.iso8601(request['expires_at']) if request['expires_at']
    value = request['raw'] ? [request.fetch('value')].pack('H*') : request.fetch('value')
    method = request['kind'] == 'verifier' ? :generate : :encrypt_and_sign
    codec.public_send(method, value, **metadata)
  else
    method = request['kind'] == 'verifier' ? :verified : :decrypt_and_verify
    value = codec.public_send(method, request.fetch('token'), **metadata)
    request['raw'] && value ? value.unpack1('H*') : value
  end
end

requests = JSON.parse(STDIN.read)
puts JSON.generate(requests.map { |request| process(request) })
