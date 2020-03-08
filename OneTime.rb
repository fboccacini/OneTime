require 'openssl'
require 'base64'
require 'base32'
require 'json'
require 'net/https'

class OneTime

  attr_reader :password

  def initialize(secret, length: 6, step: 30, encryption: 'SHA512')

    @secret = secret
    @step = step
    @encryption = encryption
    @length = length

    self.generate

  end

  def step
    return @step
  end

  def secret
    return @secret
  end

  def length
    return @length
  end

  def encryption
    return @encryption
  end

  def generate(time: Time.now)

    # Binary key from time / step
    key = ['%0.16x' % (time.to_i / self.step).to_s(16).hex].pack('H*')

    # Convert secret's non base32 char to base32 and back to string
    data = Base32.decode(Base32.encode(self.secret))

    # Get initial HMAC hash
    hash = OpenSSL::HMAC.digest(self.encryption, data, key)

    # Dynamic truncation:
    # Get the last for bit of the last byte of the hash
    offset = hash[hash.length - 1].ord & 0xf

    # Get the for bytes pointed by the offset
    hash = hash[offset .. offset + 3].bytes

    # Truncate
    truncated_hash = ((hash[0] & 0x7f) << 24) |
                     ((hash[1] & 0xff) << 16) |
                     ((hash[2] & 0xff) <<  8) |
                     (hash[3] & 0xff)

    # Get actual password
    @password = "%0.#{self.length}d" % (truncated_hash % (10 ** self.length));
    return self.password

  end

  def call_service(url, user, payload, content_type: 'application/json', accept: '*/*')

    # Base64 encode authentication for the header
    auth = Base64.strict_encode64("#{user}:#{rOTP}".encode("ASCII"))

    # Prep uri and headers
    uri = URI.parse(url)
    headers = {
        'Authorization' => "Basic #{auth}",
        'Content-Type' => content_type,
        'Accept' => accept
      }

    # Create request
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true

    # Send request
    return request.post(uri.path, payload.to_json, headers)

  end



end
