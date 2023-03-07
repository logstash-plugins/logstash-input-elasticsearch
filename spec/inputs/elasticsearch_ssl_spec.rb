require 'stud/temporary'
require "elasticsearch"

describe "SSL options" do
  let(:es_client_double) { double("Elasticsearch::Client #{self.inspect}") }
  let(:hosts) {["localhost"]}
  let(:settings) { { "ssl_enabled" => true, "hosts" => hosts } }

  subject do
    require "logstash/inputs/elasticsearch"
    LogStash::Inputs::Elasticsearch.new(settings)
  end

  before do
    allow(es_client_double).to receive(:close)
    allow(es_client_double).to receive(:ping).with(any_args).and_return(double("pong").as_null_object)
    allow(Elasticsearch::Client).to receive(:new).and_return(es_client_double)
  end

  after do
    subject.close
  end

  context "when ssl_enabled is" do
    context "true and there is no https hosts" do
      let(:hosts) { %w[http://es01 http://es01] }

      it "should not infer the ssl_enabled value" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(true)
        expect(subject.params).to match hash_including("ssl_enabled" => true)
      end
    end

    context "false and cloud_id resolve host is https" do
      let(:settings) {{
        "ssl_enabled" => false,
        "hosts" => [],
        "cloud_id" => "sample:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGFjMzFlYmI5MDI0MTc3MzE1NzA0M2MzNGZkMjZmZDQ2OjkyNDMkYTRjMDYyMzBlNDhjOGZjZTdiZTg4YTA3NGEzYmIzZTA6OTI0NA=="
      }}

      it "should not infer the ssl_enabled value" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(false)
        expect(subject.params).to match hash_including("ssl_enabled" => false)
      end
    end
  end

  context "when neither ssl nor ssl_enabled is set" do
    let(:settings) { super().reject { |k| %w[ssl ssl_enabled].include?(k) } }

    context "and there is no https hosts" do
      let(:hosts) { %w[http://es01 http://es01] }

      it "should infer the ssl_enabled value to false" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(false)
        expect(subject.params).to match hash_including("ssl_enabled" => false)
      end
    end

    context "and there is https hosts" do
      let(:hosts) { %w[https://sec-es01 https://sec-es01] }

      it "should infer the ssl_enabled value to true" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(true)
        expect(subject.params).to match hash_including("ssl_enabled" => true)
      end
    end

    context "and hosts have no scheme defined" do
      let(:hosts) { %w[es01 es01] }

      it "should infer the ssl_enabled value to false" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(false)
        expect(subject.params).to match hash_including("ssl_enabled" => false)
      end
    end

    context "and cloud_id resolved host is https" do
      let(:settings) {{
        "hosts" => [],
        "cloud_id" => "sample:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGFjMzFlYmI5MDI0MTc3MzE1NzA0M2MzNGZkMjZmZDQ2OjkyNDMkYTRjMDYyMzBlNDhjOGZjZTdiZTg4YTA3NGEzYmIzZTA6OTI0NA=="
      }}

      it "should infer the ssl_enabled value to false" do
        subject.register
        expect(subject.instance_variable_get(:@ssl_enabled)).to eql(true)
        expect(subject.params).to match hash_including("ssl_enabled" => true)
      end
    end
  end

  context "when ssl_verification_mode" do
    context "is set to none" do
      let(:settings) { super().merge(
        "ssl_verification_mode" => "none",
      ) }

      it "should print a warning" do
        expect(subject.logger).to receive(:warn).with(/You have enabled encryption but DISABLED certificate verification/).at_least(:once)
        allow(subject.logger).to receive(:warn).with(any_args)

        subject.register
      end

      it "should pass the flag to the ES client" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:ssl]).to match hash_including(:ssl => true, :verify => :disable)
        end.and_return(es_client_double)

        subject.register
      end
    end

    context "is set to full" do
      let(:settings) { super().merge(
        "ssl_verification_mode" => 'full',
      ) }

      it "should pass the flag to the ES client" do
        expect(::Elasticsearch::Client).to receive(:new) do |args|
          expect(args[:ssl]).to match hash_including(:ssl => true, :verify => :strict)
        end.and_return(es_client_double)

        subject.register
      end
    end
  end

  context "with the conflicting configs" do
    context "ssl_certificate_authorities and ssl_truststore_path set" do
      let(:ssl_truststore_path) { Stud::Temporary.file.path }
      let(:ssl_certificate_authorities_path) { Stud::Temporary.file.path }
      let(:settings) { super().merge(
        "ssl_truststore_path" => ssl_truststore_path,
        "ssl_certificate_authorities" => ssl_certificate_authorities_path
      ) }

      after :each do
        File.delete(ssl_truststore_path)
        File.delete(ssl_certificate_authorities_path)
      end

      it "should raise a configuration error" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /Use either "ssl_certificate_authorities\/ca_file" or "ssl_truststore_path"/)
      end
    end

    context "ssl_certificate and ssl_keystore_path set" do
      let(:ssl_keystore_path) { Stud::Temporary.file.path }
      let(:ssl_certificate_path) { Stud::Temporary.file.path }
      let(:settings) { super().merge(
        "ssl_certificate" => ssl_certificate_path,
        "ssl_keystore_path" => ssl_keystore_path
      ) }

      after :each do
        File.delete(ssl_keystore_path)
        File.delete(ssl_certificate_path)
      end

      it "should raise a configuration error" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /Use either "ssl_certificate" or "ssl_keystore_path\/keystore"/)
      end
    end
  end

  context "when configured with Java store files" do
    let(:ssl_truststore_path) { Stud::Temporary.file.path }
    let(:ssl_keystore_path) { Stud::Temporary.file.path }

    after :each do
      File.delete(ssl_truststore_path)
      File.delete(ssl_keystore_path)
    end

    let(:settings) { super().merge(
      "ssl_truststore_path" => ssl_truststore_path,
      "ssl_truststore_type" => "jks",
      "ssl_truststore_password" => "foo",
      "ssl_keystore_path" => ssl_keystore_path,
      "ssl_keystore_type" => "jks",
      "ssl_keystore_password" => "bar",
      "ssl_verification_mode" => "full",
      "ssl_cipher_suites" => ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
      "ssl_supported_protocols" => ["TLSv1.3"]
    ) }

    it "should pass the parameters to the ES client" do
      expect(::Elasticsearch::Client).to receive(:new) do |args|
        expect(args[:ssl]).to match hash_including(
                                      :ssl => true,
                                      :keystore => ssl_keystore_path,
                                      :keystore_type => "jks",
                                      :keystore_password => "bar",
                                      :truststore => ssl_truststore_path,
                                      :truststore_type => "jks",
                                      :truststore_password => "foo",
                                      :verify => :strict,
                                      :cipher_suites => ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
                                      :protocols => ["TLSv1.3"],
                                    )
      end.and_return(es_client_double)

      subject.register
    end
  end

  context "when configured with certificate files" do
    let(:ssl_certificate_authorities_path) { Stud::Temporary.file.path }
    let(:ssl_certificate_path) { Stud::Temporary.file.path }
    let(:ssl_key_path) { Stud::Temporary.file.path }
    let(:settings) { super().merge(
      "ssl_certificate_authorities" => [ssl_certificate_authorities_path],
      "ssl_certificate" => ssl_certificate_path,
      "ssl_key" => ssl_key_path,
      "ssl_verification_mode" => "full",
      "ssl_cipher_suites" => ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
      "ssl_supported_protocols" => ["TLSv1.3"]
    ) }

    after :each do
      File.delete(ssl_certificate_authorities_path)
      File.delete(ssl_certificate_path)
      File.delete(ssl_key_path)
    end

    it "should pass the parameters to the ES client" do
      expect(::Elasticsearch::Client).to receive(:new) do |args|
        expect(args[:ssl]).to match hash_including(
                                      :ssl => true,
                                      :ca_file => ssl_certificate_authorities_path,
                                      :client_cert => ssl_certificate_path,
                                      :client_key => ssl_key_path,
                                      :verify => :strict,
                                      :cipher_suites => ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
                                      :protocols => ["TLSv1.3"],
                                    )
      end.and_return(es_client_double)

      subject.register
    end

    context "and only the ssl_certificate is set" do
      let(:settings) { super().reject { |k| "ssl_key".eql?(k) } }

      it "should raise a configuration error" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /You must set both "ssl_certificate" and "ssl_key"/)
      end
    end

    context "and only the ssl_key is set" do
      let(:settings) { super().reject { |k| "ssl_certificate".eql?(k) } }

      it "should raise a configuration error" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /You must set both "ssl_certificate" and "ssl_key"/)
      end
    end
  end
end

