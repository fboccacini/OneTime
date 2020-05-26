//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
//   OneTime password generator - 2020 fboccacini@gmail.com <Fabio Boccacini>   //
//   v1.0                                                                       //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////

class OneTime{

  constructor(secret, length = 6, step = 30, encryption = 'SHA1'){

    this.secret = secret
    this.length = length
    this.step = step
    this.encryption = encryption

  }

  generate(time = Time.now(),
                length = this.length,
                step = this.step,
                encryption = this.encryption){

    try{

      // Binary key from time / step
      key = ['%0.16x' % (time.to_i / step).to_s(16).hex].pack('H*')

      // Convert secret's non base32 char to base32 and back to string
      data = Base32.decode(Base32.encode(self.secret))

      // Get initial HMAC hash
      require("crypto").createHmac(this.encryption, data)
              .update(counter)
              .digest("hex");
      // hash = OpenSSL::HMAC.digest(encryption, data, key)

      // Dynamic truncation:
      // Get the last for bit of the last byte of the hash
      offset = hash[hash.length - 1].ord & 0xf

      // Get the for bytes pointed by the offset
      hash = hash[offset .. offset + 3].bytes

      // Get new hash
      truncated_hash = ((hash[0] & 0x7f) << 24) |
                       ((hash[1] & 0xff) << 16) |
                       ((hash[2] & 0xff) <<  8) |
                       (hash[3] & 0xff)

      // Get actual password
      this.password = "%0.#{length}d" % (truncated_hash % (10 ** length));
      return this.password

    }
    catch(e){
      console.log(e.message)
      // puts e.backtrace.join("\n")
      return null
    }
  }
}

module.exports = OneTime
