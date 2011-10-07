module Savon

  # Savon::WSSE
  #
  # Represents parameters for WSSE authentication.
  class WSSE

    # Base address for WSSE docs.
    BaseAddress = "http://docs.oasis-open.org/wss/2004/01"

    # Namespace for WS Security Secext.
    WSENamespace = "#{BaseAddress}/oasis-200401-wss-wssecurity-secext-1.0.xsd"

    # Namespace for WS Security Utility.
    WSUNamespace = "#{BaseAddress}/oasis-200401-wss-wssecurity-utility-1.0.xsd"

    # URI for "wsse:Password/@Type" #PasswordText.
    PasswordTextURI = "#{BaseAddress}/oasis-200401-wss-username-token-profile-1.0#PasswordText"

    # URI for "wsse:Password/@Type" #PasswordDigest.
    PasswordDigestURI = "#{BaseAddress}/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"

    # Global WSSE username.
    @@username = nil

    # Returns the global WSSE username.
    def self.username
      @@username
    end

    # Sets the global WSSE username.
    def self.username=(username)
      @@username = username.nil? ? nil : username.to_s
    end

    # Global WSSE password.
    @@password = nil

    # Returns the global WSSE password.
    def self.password
      @@password
    end

    # Sets the global WSSE password.
    def self.password=(password)
      @@password = password.nil? ? nil : password.to_s
    end

    # Global setting of whether to use WSSE digest.
    @@digest = false

    # Returns the global setting of whether to use WSSE digest.
    def self.digest?
      @@digest
    end

    # Global setting of whether to use WSSE digest.
    def self.digest=(digest)
      @@digest = digest
    end

    # Sets the WSSE username per request.
    def username=(username)
      @username = username.nil? ? nil : username.to_s
    end

    # Returns the WSSE username. Defaults to the global setting.
    def username
      @username || self.class.username
    end

    # Sets the WSSE password per request.
    def password=(password)
      @password = password.nil? ? nil : password.to_s
    end

    # Returns the WSSE password. Defaults to the global setting.
    def password
      @password || self.class.password
    end

    # Sets whether to use WSSE digest per request.
    attr_writer :digest

    # Returns whether to use WSSE digest. Defaults to the global setting. 
    def digest?
      @digest || self.class.digest?
    end

    # Returns the XML for a WSSE header or an empty String unless both
    # username and password were specified.
    def header
      return "" unless username && password
      
      # test: this is unnecessary if subsequent requests have new timestamps
      created = Time.new.getutc
      expires = 5.minutes.from(created)
      secret = OpenSSL::Random.random_bytes(20).toutf8.strip

      builder = Builder::XmlMarkup.new
      builder.wsse :Security, "env:mustUnderstand" => "1" do |xml|
        xml.wsu :Timestamp, "wsu:Id" => "Timestamp-#{UUID.generate}" do
          xml.wsu :Created,   timestamp(created)
          xml.wsu :Expires,   timestamp(expires)
        end
        xml.wsse :UsernameToken, "wsu:Id" => "SecurityToken-#{UUID.generate}" do
          xml.wsse :Username, username
          xml.wsse :Password, password_node(secret, created), :Type => password_type
          xml.wsu  :Created,  timestamp(created)
          xml.wsse :Nonce,    nonce(secret)
        end
      end
    end

  private

    # Returns the WSSE password. Encrypts the password for digest authentication.
    def password_node(nonce, created)
      return password unless digest?
      token = nonce + timestamp(created) + password
      Base64.encode64(Digest::SHA1.new.update(token).digest)
    end
    
    def nonce(secret)
      Base64.encode64(secret).encode("utf-8")
    end

    # Returns the URI for the "wsse:Password/@Type" attribute.
    def password_type
      digest? ? PasswordDigestURI : PasswordTextURI
    end

=begin
    # Returns a WSSE nonce.
    def nonce
#     @nonce ||= Digest::SHA1.hexdigest String.random + timestamp
      @nonce ||= Base64.encode64(OpenSSL::Random.random_bytes(20).to_s().strip())
    end
=end

    # Returns a WSSE timestamp.
    def timestamp(time)
      # @timestamp ||= Time.now.getutc().strftime Savon::SOAP::DateTimeFormat
      time.strftime(Savon::SOAP::DateTimeFormat).encode("utf-8")
    end

  end
end
