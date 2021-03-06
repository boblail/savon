require "spec_helper"

describe Savon::SOAP do
  before do
    @authenticate_operation = WSDLFixture.authentication(:operations)[:authenticate]
    @soap = Savon::SOAP.new @authenticate_operation, EndpointHelper.soap_endpoint
  end

  it "contains the SOAP namespace for each supported SOAP version" do
    Savon::SOAP::Versions.each do |soap_version|
      Savon::SOAP::Namespace[soap_version].should be_a(String)
      Savon::SOAP::Namespace[soap_version].should_not be_empty
    end
  end

  it "contains the Content-Types for each supported SOAP version" do
    Savon::SOAP::Versions.each do |soap_version|
      Savon::SOAP::ContentType[soap_version].should be_a(String)
      Savon::SOAP::ContentType[soap_version].should_not be_empty
    end
  end

  it "contains an Array of supported SOAP versions" do
    Savon::SOAP::Versions.should be_an(Array)
    Savon::SOAP::Versions.should_not be_empty
  end

  it "contains the xs:dateTime format" do
    Savon::SOAP::DateTimeFormat.should be_a(String)
    Savon::SOAP::DateTimeFormat.should_not be_empty

    DateTime.new(2012, 03, 22, 16, 22, 33).strftime(Savon::SOAP::DateTimeFormat).
      should == "2012-03-22T16:22:33Z"
  end

  it "contains a Regexp matching the xs:dateTime format" do
    Savon::SOAP::DateTimeRegexp.should be_a(Regexp)
    (Savon::SOAP::DateTimeRegexp === "2012-03-22T16:22:33").should be_true
  end

  it "defaults to SOAP 1.1" do
    Savon::SOAP.version.should == 1
  end

  it "has both getter and setter for the SOAP version to use (global setting)" do
    [2, 1].each do |soap_version|
      Savon::SOAP.version = soap_version
      Savon::SOAP.version.should == soap_version
    end
  end

  it "has a setter for the Savon::WSSE" do
    @soap.wsse = Savon::WSSE.new
  end

  it "has both getter and setter for the SOAP action" do
    @soap.action.should == @authenticate_operation[:action]

    @soap.action = "someAction"
    @soap.action.should == "someAction"
  end

  it "has both getter and setter for the SOAP input" do
    @soap.input.should == @authenticate_operation[:input]

    @soap.input = "whatever"
    @soap.input.should == "whatever"

    args = "FindUserRequest", { "username" => "auser", "anotherAttr" => "someVal" }
    @soap.input = *args
    @soap.input.should == [*args]
  end

  it "has both getter and setter for global SOAP headers" do
    header = { "some" => "header" }
    Savon::SOAP.header = header
    Savon::SOAP.header.should == header

    Savon::SOAP.header = {}
  end

  it "has both getter and setter for the SOAP header" do
    @soap.header.should be_a(Hash)
    @soap.header.should be_empty

    @soap.header = { "specialAuthKey" => "secret" }
    @soap.header.should == { "specialAuthKey" => "secret" }
  end

  it "has a getter for the SOAP body, expecting a Hash or an XML String" do
    @soap.body = { :id => 666 }
    @soap.body = "<id>666</id>"
  end

  it "has a setter for specifying a Hash of namespaces" do
    namespaces = { "xmlns:env" => "http://example.com" }
    @soap.namespaces = namespaces
    @soap.namespaces.should == namespaces
  end

  describe "has a getter for namespaces" do
    it "which defaults to include the SOAP 1.1 namespace" do
      @soap.namespaces.should == { "xmlns:env" => Savon::SOAP::Namespace[1] }
    end

    it "which contains the SOAP 1.2 namespace if specified" do
      @soap.version = 2
      @soap.namespaces.should == { "xmlns:env" => Savon::SOAP::Namespace[2] }
    end
  end

  it "has both getter and setter for global namespaces" do
    namespaces = { "some" => "namespace" }
    Savon::SOAP.namespaces = namespaces
    Savon::SOAP.namespaces.should == namespaces

    Savon::SOAP.namespaces = {}
  end

  it "has a convenience method for setting the 'xmlns:wsdl' namespace" do
    @soap.namespaces.should == { "xmlns:env" => "http://schemas.xmlsoap.org/soap/envelope/" }

    @soap.namespace = "http://example.com"
    @soap.namespaces.should include("xmlns:env" => "http://schemas.xmlsoap.org/soap/envelope/")
    @soap.namespaces.should include("xmlns:wsdl" => "http://example.com")
  end

  it "has both getter and setter for the SOAP endpoint" do
    soap_endpoint = URI EndpointHelper.soap_endpoint

    @soap.endpoint = soap_endpoint
    @soap.endpoint.should == soap_endpoint
  end

  it "has a getter for the SOAP version to use which defaults to SOAP 1.1" do
    @soap.version.should == Savon::SOAP.version
  end

  it "has a setter for specifying the SOAP version to use" do
    @soap.version = 2
    @soap.version.should == 2
  end

  describe "to_xml" do
    after { Savon::SOAP.version = 1 }

    it "returns the XML for a SOAP request" do
      @soap.namespaces["xmlns:wsdl"] = "http://v1_0.ws.auth.order.example.com/"
      @soap.body = { :id => 666 }

      xml = @soap.to_xml
      xml.should include('xmlns:wsdl="http://v1_0.ws.auth.order.example.com/"')
      xml.should include('xmlns:env="http://schemas.xmlsoap.org/soap/envelope/"')
      xml.should include('<wsdl:authenticate><id>666</id></wsdl:authenticate>')
    end

    it "does not include an empty header tag" do
      @soap.to_xml.should_not include('env:Header')
    end
    
    it "returns the appropriate XML for a SOAP Body's root node when parameters are present" do
      @soap.input = "authenticate", { "protocol" => "tls", "version" => "1.2" }
      @soap.body = { :id => 666 }

      @soap.to_xml.should include('<wsdl:authenticate protocol="tls" version="1.2"><id>666</id></wsdl:authenticate>')
    end

    it "caches the XML, returning the same Object every time" do
      @soap.to_xml.object_id.should == @soap.to_xml.object_id
    end

    it "uses the SOAP namespace for the specified SOAP version" do
      @soap.version = 2
      @soap.to_xml.should include(Savon::SOAP::Namespace[2])
    end

    it "uses the SOAP namespace for the default SOAP version otherwise" do
      Savon::SOAP.version = 2
      @soap.to_xml.should include(Savon::SOAP::Namespace[2])
    end

    it "merges global and per request headers defined as Hashes" do
      Savon::SOAP.header = { "API-KEY" => "secret", "SOME-KEY" => "something" }
      @soap.header["SOME-KEY"] = "somethingelse"

      @soap.to_xml.should include("<API-KEY>secret</API-KEY>")
      @soap.to_xml.should include("<SOME-KEY>somethingelse</SOME-KEY>")
    end

    it "joins global and per request headers defined as Strings" do
      Savon::SOAP.header = "<API-KEY>secret</API-KEY>"
      @soap.header = "<SOME-KEY>somethingelse</SOME-KEY>"

      @soap.to_xml.should include("<API-KEY>secret</API-KEY>")
      @soap.to_xml.should include("<SOME-KEY>somethingelse</SOME-KEY>")
    end

    it "merges the global and per request namespaces" do
      Savon::SOAP.namespaces = { "xmlns:wsdl" => "namespace", "xmlns:v1" => "v1namespace" }
      @soap.namespaces["xmlns:v1"] = "newV1namespace"

      @soap.to_xml.should include('xmlns:wsdl="namespace"')
      @soap.to_xml.should include('xmlns:v1="newV1namespace"')
    end
  end

end
