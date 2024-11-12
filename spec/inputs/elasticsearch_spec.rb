# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/inputs/elasticsearch"
require "elasticsearch"
require "timecop"
require "stud/temporary"
require "time"
require "date"
require "cabin"
require "webrick"
require "uri"

require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

describe LogStash::Inputs::Elasticsearch, :ecs_compatibility_support do

  let(:plugin) { described_class.new(config) }
  let(:queue) { Queue.new }
  let(:build_flavor) { "default" }
  let(:es_version) { "7.5.0" }
  let(:cluster_info) { {"version" => {"number" => es_version, "build_flavor" => build_flavor}, "tagline" => "You Know, for Search"} }

  before(:each) do
    Elasticsearch::Client.send(:define_method, :ping) { } # define no-action ping method
    allow_any_instance_of(Elasticsearch::Client).to receive(:info).and_return(cluster_info)
  end

  let(:base_config) do
    {
        'hosts' => ["localhost"],
        'query' => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
    }
  end

  context "register" do
    let(:config) do
      {
        "schedule" => "* * * * * UTC"
      }
    end

    context "against authentic Elasticsearch" do
      it "should not raise an exception" do
       expect { plugin.register }.to_not raise_error
      end

      it "does not set header Elastic-Api-Version" do
        plugin.register
        client = plugin.send(:client)
        expect( extract_transport(client).options[:transport_options][:headers] ).not_to match hash_including("Elastic-Api-Version" => "2023-10-31")
      end

      it "sets an x-elastic-product-origin header identifying this as an internal plugin request" do
        plugin.register
        client = plugin.send(:client)
        expect( extract_transport(client).options[:transport_options][:headers] ).to match hash_including("x-elastic-product-origin"=>"logstash-input-elasticsearch")
      end
    end

    context "against not authentic Elasticsearch" do
      before(:each) do
         Elasticsearch::Client.send(:define_method, :ping) { raise Elasticsearch::UnsupportedProductError.new("Fake error") } # define error ping method
      end

      it "should raise ConfigurationError" do
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "against serverless Elasticsearch" do
      before do
        allow(plugin).to receive(:test_connection!)
        allow(plugin).to receive(:serverless?).and_return(true)
      end

      context "with unsupported header" do
        let(:es_client) { double("es_client") }

        before do
          allow(Elasticsearch::Client).to receive(:new).and_return(es_client)
          allow(es_client).to receive(:info).and_raise(
            Elasticsearch::Transport::Transport::Errors::BadRequest.new
          )
        end

        it "raises an exception" do
          expect {plugin.register}.to raise_error(LogStash::ConfigurationError)
        end
      end

      context "with supported header" do
        it "set default header to rest client" do
          expect_any_instance_of(Elasticsearch::Client).to receive(:info).and_return(true)
          plugin.register
          client = plugin.send(:client)
          expect( extract_transport(client).options[:transport_options][:headers] ).to match hash_including("Elastic-Api-Version" => "2023-10-31")
        end

        it "sets an x-elastic-product-origin header identifying this as an internal plugin request" do
          plugin.register
          client = plugin.send(:client)
          expect( extract_transport(client).options[:transport_options][:headers] ).to match hash_including("x-elastic-product-origin"=>"logstash-input-elasticsearch")
        end
      end
    end

    context "retry" do
      let(:config) do
        {
          "retries" => -1
        }
      end
      it "should raise an exception with negative number" do
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "search_api" do
      before(:each) do
        plugin.register
      end

      context "ES 8" do
        let(:es_version) { "8.10.0" }
        it "resolves `auto` to `search_after`" do
          expect(plugin.instance_variable_get(:@query_executor)).to be_a LogStash::Inputs::Elasticsearch::SearchAfter
        end
      end

      context "ES 7" do
        let(:es_version) { "7.17.0" }
        it "resolves `auto` to `scroll`" do
          expect(plugin.instance_variable_get(:@query_executor)).to be_a LogStash::Inputs::Elasticsearch::Scroll
        end
      end
    end
  end

  it_behaves_like "an interruptible input plugin" do
    let(:config) do
      {
        "schedule" => "* * * * * UTC"
      }
    end

    before :each do
      @esclient = double("elasticsearch-client")
      allow(Elasticsearch::Client).to receive(:new).and_return(@esclient)
      hit = {
        "_index" => "logstash-2014.10.12",
        "_type" => "logs",
        "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
        "_score" => 1.0,
        "_source" => { "message" => ["ohayo"] }
      }
      allow(@esclient).to receive(:search) { { "hits" => { "hits" => [hit] } } }
      allow(@esclient).to receive(:scroll) { { "hits" => { "hits" => [hit] } } }
      allow(@esclient).to receive(:clear_scroll).and_return(nil)
      allow(@esclient).to receive(:ping)
      allow(@esclient).to receive(:info).and_return(cluster_info)
    end
  end


  ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

    before(:each) do
      allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
    end

    let(:config) do
      {
          'hosts' => ["localhost"],
          'query' => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
      }
    end

    let(:mock_response) do
      {
          "_scroll_id" => "cXVlcnlUaGVuRmV0Y2g",
          "took" => 27,
          "timed_out" => false,
          "_shards" => {
              "total" => 169,
              "successful" => 169,
              "failed" => 0
          },
          "hits" => {
              "total" => 1,
              "max_score" => 1.0,
              "hits" => [ {
                              "_index" => "logstash-2014.10.12",
                              "_type" => "logs",
                              "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
                              "_score" => 1.0,
                              "_source" => { "message" => ["ohayo"] }
                          } ]
          }
      }
    end

    let(:mock_scroll_response) do
      {
          "_scroll_id" => "r453Wc1jh0caLJhSDg",
          "hits" => { "hits" => [] }
      }
    end

    before(:each) do
      client = Elasticsearch::Client.new
      expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
      expect(client).to receive(:search).with(any_args).and_return(mock_response)
      expect(client).to receive(:scroll).with({ :body => { :scroll_id => "cXVlcnlUaGVuRmV0Y2g" }, :scroll=> "1m" }).and_return(mock_scroll_response)
      expect(client).to receive(:clear_scroll).and_return(nil)
      expect(client).to receive(:ping)
    end

    before { plugin.register }

    it 'creates the events from the hits' do
      plugin.run queue
      event = queue.pop

      expect(event).to be_a(LogStash::Event)
      expect(event.get("message")).to eql [ "ohayo" ]
    end

    context 'when a target is set' do
      let(:config) do
        {
            'hosts' => ["localhost"],
            'query' => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }',
            'target' => "[@metadata][_source]"
        }
      end

      it 'creates the event using the target' do
        plugin.run queue
        event = queue.pop

        expect(event).to be_a(LogStash::Event)
        expect(event.get("[@metadata][_source][message]")).to eql [ "ohayo" ]
      end
    end

  end

  # This spec is an adapter-spec, ensuring that we send the right sequence of messages to our Elasticsearch Client
  # to support sliced scrolling. The underlying implementation will spawn its own threads to consume, so we must be
  # careful to use thread-safe constructs.
  context "with managed sliced scrolling" do
    let(:config) do
      {
          'query' => "#{LogStash::Json.dump(query)}",
          'slices' => slices,
          'docinfo' => true, # include ids
          'docinfo_target' => '[@metadata]'
      }
    end
    let(:query) do
      {
        "query" => {
          "match" => { "city_name" => "Okinawa" }
        },
        "fields" => ["message"]
      }
    end
    let(:slices) { 2 }

    context 'with `slices => 0`' do
      let(:slices) { 0 }
      it 'fails to register' do
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context 'with `slices => 1`' do
      let(:slices) { 1 }
      before { plugin.register }

      it 'runs just one slice' do
        expect(plugin.instance_variable_get(:@query_executor)).to receive(:search).with(duck_type(:<<), nil)
        expect(Thread).to_not receive(:new)

        plugin.run([])
      end
    end

    context 'without slices directive' do
      let(:config) { super().tap { |h| h.delete('slices') } }
      before { plugin.register }

      it 'runs just one slice' do
        expect(plugin.instance_variable_get(:@query_executor)).to receive(:search).with(duck_type(:<<), nil)
        expect(Thread).to_not receive(:new)

        plugin.run([])
      end
    end

    2.upto(8) do |slice_count|
      context "with `slices => #{slice_count}`" do
        let(:slices) { slice_count }
        before { plugin.register }

        it "runs #{slice_count} independent slices" do
          expect(Thread).to receive(:new).and_call_original.exactly(slice_count).times
          slice_count.times do |slice_id|
            expect(plugin.instance_variable_get(:@query_executor)).to receive(:search).with(duck_type(:<<), slice_id)
          end

          plugin.run([])
        end
      end
    end

    # This section of specs heavily mocks the Elasticsearch::Client, and ensures that the Elasticsearch Input Plugin
    # behaves as expected when handling a series of sliced, scrolled requests/responses.
    context 'adapter/integration' do
      let(:response_template) do
        {
            "took" => 12,
            "timed_out" => false,
            "shards" => {
                "total" => 6,
                "successful" => 6,
                "failed" => 0
            }
        }
      end

      let(:hits_template) do
        {
            "total" => 4,
            "max_score" => 1.0,
            "hits" => []
        }
      end

      let(:hit_template) do
        {
            "_index" => "logstash-2018.08.23",
            "_type" => "logs",
            "_score" => 1.0,
            "_source" => { "message" => ["hello, world"] }
        }
      end

      # BEGIN SLICE 0: a sequence of THREE scrolled responses containing 2, 1, and 0 items
      # end-of-slice is reached when slice0_response2 is empty.
      begin
        let(:slice0_response0) do
          response_template.merge({
              "_scroll_id" => slice0_scroll1,
              "hits" => hits_template.merge("hits" => [
                  hit_template.merge('_id' => "slice0-response0-item0"),
                  hit_template.merge('_id' => "slice0-response0-item1")
                  ])
          })
        end
        let(:slice0_scroll1) { 'slice:0,scroll:1' }
        let(:slice0_response1) do
          response_template.merge({
              "_scroll_id" => slice0_scroll2,
              "hits" => hits_template.merge("hits" => [
                  hit_template.merge('_id' => "slice0-response1-item0")
              ])
          })
        end
        let(:slice0_scroll2) { 'slice:0,scroll:2' }
        let(:slice0_response2) do
          response_template.merge(
              "_scroll_id" => slice0_scroll3,
              "hits" => hits_template.merge({"hits" => []})
          )
        end
        let(:slice0_scroll3) { 'slice:0,scroll:3' }
      end
      # END SLICE 0

      # BEGIN SLICE 1: a sequence of TWO scrolled responses containing 2 and 2 items.
      # end-of-slice is reached when slice1_response1 does not contain a next scroll id
      begin
        let(:slice1_response0) do
          response_template.merge({
              "_scroll_id" => slice1_scroll1,
              "hits" => hits_template.merge("hits" => [
                  hit_template.merge('_id' => "slice1-response0-item0"),
                  hit_template.merge('_id' => "slice1-response0-item1")
              ])
          })
        end
        let(:slice1_scroll1) { 'slice:1,scroll:1' }
        let(:slice1_response1) do
          response_template.merge({
              "hits" => hits_template.merge("hits" => [
                  hit_template.merge('_id' => "slice1-response1-item0"),
                  hit_template.merge('_id' => "slice1-response1-item1")
              ])
          })
        end
      end
      # END SLICE 1


      # RSpec mocks validations are not threadsafe.
      # Allow caller to synchronize.
      def synchronize_method!(object, method_name)
        original_method = object.method(method_name)
        mutex = Mutex.new
        allow(object).to receive(method_name).with(any_args) do |*method_args, &method_block|
          mutex.synchronize do
            original_method.call(*method_args,&method_block)
          end
        end
      end

      describe "with normal response" do
        before(:each) do
          expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
          plugin.register

          expect(client).to receive(:clear_scroll).and_return(nil)

          # SLICE0 is a three-page scroll in which the last page is empty
          slice0_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 0, 'max' => 2}))
          expect(client).to receive(:search).with(hash_including(:body => slice0_query)).and_return(slice0_response0)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll1 })).and_return(slice0_response1)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll2 })).and_return(slice0_response2)
          allow(client).to receive(:ping)

          # SLICE1 is a two-page scroll in which the last page has no next scroll id
          slice1_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 1, 'max' => 2}))
          expect(client).to receive(:search).with(hash_including(:body => slice1_query)).and_return(slice1_response0)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice1_scroll1 })).and_return(slice1_response1)

          synchronize_method!(plugin.instance_variable_get(:@query_executor), :next_page)
          synchronize_method!(plugin.instance_variable_get(:@query_executor), :initial_search)
        end

        let(:client) { Elasticsearch::Client.new }

        let(:emitted_events) do
          queue = Queue.new # since we are running slices in threads, we need a thread-safe queue.
          plugin.run(queue)
          events = []
          events << queue.pop until queue.empty?
          events
        end

        let(:emitted_event_ids) do
          emitted_events.map { |event| event.get('[@metadata][_id]') }
        end

        it 'emits the hits on the first page of the first slice' do
          expect(emitted_event_ids).to include('slice0-response0-item0')
          expect(emitted_event_ids).to include('slice0-response0-item1')
        end
        it 'emits the hits on the second page of the first slice' do
          expect(emitted_event_ids).to include('slice0-response1-item0')
        end

        it 'emits the hits on the first page of the second slice' do
          expect(emitted_event_ids).to include('slice1-response0-item0')
          expect(emitted_event_ids).to include('slice1-response0-item1')
        end

        it 'emits the hits on the second page of the second slice' do
          expect(emitted_event_ids).to include('slice1-response1-item0')
          expect(emitted_event_ids).to include('slice1-response1-item1')
        end

        it 'does not double-emit' do
          expect(emitted_event_ids.uniq).to eq(emitted_event_ids)
        end

        it 'emits events with appropriate fields' do
          emitted_events.each do |event|
            expect(event).to be_a(LogStash::Event)
            expect(event.get('message')).to eq(['hello, world'])
            expect(event.get('[@metadata][_id]')).to_not be_nil
            expect(event.get('[@metadata][_id]')).to_not be_empty
            expect(event.get('[@metadata][_index]')).to start_with('logstash-')
          end
        end
      end

      describe "with scroll request fail" do
        before(:each) do
          expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
          plugin.register

          expect(client).to receive(:clear_scroll).twice.and_return(nil)

          # SLICE0 is a three-page scroll
          slice0_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 0, 'max' => 2}))
          expect(client).to receive(:search).with(hash_including(:body => slice0_query)).and_return(slice0_response0)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll1 })).and_return(slice0_response1)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll2 })).and_return(slice0_response2)
          allow(client).to receive(:ping)

          # SLICE1 is a two-page scroll in which the last page throws exception
          slice1_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 1, 'max' => 2}))
          expect(client).to receive(:search).with(hash_including(:body => slice1_query)).and_return(slice1_response0)
          expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice1_scroll1 })).and_raise("boom")

          synchronize_method!(plugin.instance_variable_get(:@query_executor), :next_page)
          synchronize_method!(plugin.instance_variable_get(:@query_executor), :initial_search)
        end

        let(:client) { Elasticsearch::Client.new }

        it 'insert event to queue without waiting other slices' do
          expect(plugin.instance_variable_get(:@query_executor)).to receive(:search).twice.and_wrap_original do |m, *args|
            q = args[0]
            slice_id = args[1]
            if slice_id == 0
              m.call(*args)
              expect(q.size).to eq(3)
            else
              sleep(1)
              m.call(*args)
            end
          end

          queue = Queue.new
          plugin.run(queue)
          expect(queue.size).to eq(5)
        end
      end
    end
  end

  context "with Elasticsearch document information" do
    let!(:response) do
      {
        "_scroll_id" => "cXVlcnlUaGVuRmV0Y2g",
        "took" => 27,
        "timed_out" => false,
        "_shards" => {
          "total" => 169,
          "successful" => 169,
          "failed" => 0
        },
        "hits" => {
          "total" => 1,
          "max_score" => 1.0,
          "hits" => [ {
            "_index" => "logstash-2014.10.12",
            "_type" => "logs",
            "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
            "_score" => 1.0,
            "_source" => {
              "message" => ["ohayo"],
              "metadata_with_hash" => { "awesome" => "logstash" },
              "metadata_with_string" => "a string"
            }
          } ]
        }
      }
    end

    let(:scroll_reponse) do
      {
        "_scroll_id" => "r453Wc1jh0caLJhSDg",
        "hits" => { "hits" => [] }
      }
    end

    let(:client) { Elasticsearch::Client.new }

    before do
      expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
      expect(client).to receive(:search).with(any_args).and_return(response)
      allow(client).to receive(:scroll).with({ :body => {:scroll_id => "cXVlcnlUaGVuRmV0Y2g"}, :scroll => "1m" }).and_return(scroll_reponse)
      allow(client).to receive(:clear_scroll).and_return(nil)
      allow(client).to receive(:ping).and_return(nil)
    end

    ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      before do
        if do_register
          plugin.register
          plugin.run queue
        end
      end

      let(:do_register) { true }

      let(:event) { queue.pop }

      context 'with docinfo enabled' do
        let(:config) { base_config.merge 'docinfo' => true }

        it "provides document info under metadata" do
          if ecs_select.active_mode == :disabled
            expect(event.get("[@metadata][_index]")).to eq('logstash-2014.10.12')
            expect(event.get("[@metadata][_type]")).to eq('logs')
            expect(event.get("[@metadata][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
          else
            expect(event.get("[@metadata][input][elasticsearch][_index]")).to eq('logstash-2014.10.12')
            expect(event.get("[@metadata][input][elasticsearch][_type]")).to eq('logs')
            expect(event.get("[@metadata][input][elasticsearch][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
          end
        end

        context 'with docinfo_target' do
          let(:config) { base_config.merge 'docinfo' => true, 'docinfo_target' => docinfo_target }
          let(:docinfo_target) { 'metadata_with_hash' }

          it 'merges values if the `docinfo_target` already exist in the `_source` document' do
            expect(event.get("[metadata_with_hash][_index]")).to eq('logstash-2014.10.12')
            expect(event.get("[metadata_with_hash][_type]")).to eq('logs')
            expect(event.get("[metadata_with_hash][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
            expect(event.get("[metadata_with_hash][awesome]")).to eq("logstash")
          end

          context 'non-existent' do
            let(:docinfo_target) { 'meta' }

            it 'should move the document information to the specified field' do
              expect(event.get("[meta][_index]")).to eq('logstash-2014.10.12')
              expect(event.get("[meta][_type]")).to eq('logs')
              expect(event.get("[meta][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
            end

          end

        end

        context 'if the `docinfo_target` exist but is not of type hash' do
          let(:config) { base_config.merge 'docinfo' => true, "docinfo_target" => 'metadata_with_string' }
          let(:do_register) { false }

          it 'raises an exception if the `docinfo_target` exist but is not of type hash' do
            expect(client).not_to receive(:clear_scroll)
            plugin.register
            expect { plugin.run([]) }.to raise_error(Exception, /incompatible event/)
          end

        end

        context 'with docinfo_fields' do
          let(:config) { base_config.merge 'docinfo' => true, "docinfo_fields" => ["_index"] }

          it "allows to specify which fields from the document info to save to metadata" do
            meta_base = event.get(ecs_select.active_mode == :disabled ? "@metadata" : "[@metadata][input][elasticsearch]")
            expect(meta_base.keys).to eql ["_index"]
          end

        end

        context 'add_field' do
          let(:config) { base_config.merge 'docinfo' => true,
                                           'add_field' => { 'identifier' => "foo:%{[@metadata][_type]}:%{[@metadata][_id]}" } }

          it 'should be able to reference metadata fields in `add_field` decorations' do
            expect(event.get('identifier')).to eq('foo:logs:C5b2xLQwTZa76jBmHIbwHQ')
          end if ecs_select.active_mode == :disabled

        end

      end

      context "when not defining the docinfo" do
        let(:config) { base_config }

        it 'should keep the document information in the root of the event' do
          expect(event.get("[@metadata]")).to be_empty
        end
      end

    end
  end

  describe "client" do
    let(:config) do
      {

      }
    end
    let(:plugin) { described_class.new(config) }
    let(:event)  { LogStash::Event.new({}) }

    describe "cloud.id" do
      let(:valid_cloud_id) do
        'sample:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGFjMzFlYmI5MDI0MTc3MzE1NzA0M2MzNGZkMjZmZDQ2OjkyNDMkYTRjMDYyMzBlNDhjOGZjZTdiZTg4YTA3NGEzYmIzZTA6OTI0NA=='
      end

      let(:config) { super().merge({ 'cloud_id' => valid_cloud_id }) }

      it "should set host(s)" do
        plugin.register
        client = plugin.send(:client)

        expect( client.transport.instance_variable_get(:@seeds) ).to eql [{
                                                                              :scheme => "https",
                                                                              :host => "ac31ebb90241773157043c34fd26fd46.us-central1.gcp.cloud.es.io",
                                                                              :port => 9243,
                                                                              :path => "",
                                                                              :protocol => "https"
                                                                          }]
      end

      context 'invalid' do
        let(:config) { super().merge({ 'cloud_id' => 'invalid:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlv' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id.*? is invalid/
        end
      end

      context 'hosts also set' do
        let(:config) { super().merge({ 'cloud_id' => valid_cloud_id, 'hosts' => [ 'localhost:9200' ] }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_id and hosts/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "cloud.auth" do
      let(:config) { super().merge({ 'cloud_auth' => LogStash::Util::Password.new('elastic:my-passwd-00') }) }

      it "should set authorization" do
        plugin.register
        client = plugin.send(:client)
        auth_header = extract_transport(client).options[:transport_options][:headers]['Authorization']

        expect( auth_header ).to eql "Basic #{Base64.encode64('elastic:my-passwd-00').rstrip}"
      end

      context 'invalid' do
        let(:config) { super().merge({ 'cloud_auth' => 'invalid-format' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /cloud_auth.*? format/
        end
      end

      context 'user also set' do
        let(:config) { super().merge({ 'cloud_auth' => 'elastic:my-passwd-00', 'user' => 'another' }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "api_key" do
      context "without ssl" do
        let(:config) { super().merge({ 'api_key' => LogStash::Util::Password.new('foo:bar') }) }

        it "should fail" do
          expect { plugin.register }.to raise_error LogStash::ConfigurationError, /api_key authentication requires SSL\/TLS/
        end
      end

      context "with ssl" do
        let(:config) { super().merge({ 'api_key' => LogStash::Util::Password.new('foo:bar'), "ssl_enabled" => true }) }

        it "should set authorization" do
          plugin.register
          client = plugin.send(:client)
          auth_header = extract_transport(client).options[:transport_options][:headers]['Authorization']

          expect( auth_header ).to eql "ApiKey #{Base64.strict_encode64('foo:bar')}"
        end

        context 'user also set' do
          let(:config) { super().merge({ 'api_key' => 'foo:bar', 'user' => 'another' }) }

          it "should fail" do
            expect { plugin.register }.to raise_error LogStash::ConfigurationError, /Multiple authentication options are specified/
          end
        end
        
        context 'ssl verification disabled' do
          let(:config) { super().merge({ 'ssl_verification_mode' => 'none' }) }
          it 'should warn data security risk' do
            expect(plugin.logger).to receive(:warn).once.with("You have enabled encryption but DISABLED certificate verification, to make sure your data is secure set `ssl_verification_mode => full`")
            plugin.register
          end
        end
      end
    end if LOGSTASH_VERSION > '6.0'

    describe "proxy" do
      let(:config) { super().merge({ 'proxy' => 'http://localhost:1234' }) }

      it "should set proxy" do
        plugin.register
        client = plugin.send(:client)
        proxy = extract_transport(client).options[:transport_options][:proxy]

        expect( proxy ).to eql "http://localhost:1234"
      end

      context 'invalid' do
        let(:config) { super().merge({ 'proxy' => '${A_MISSING_ENV_VAR:}' }) }

        it "should not set proxy" do
          plugin.register
          client = plugin.send(:client)

          expect( extract_transport(client).options[:transport_options] ).to_not include(:proxy)
        end
      end
    end

    class StoppableServer

      attr_reader :port

      def initialize()
        queue = Queue.new
        @first_req_waiter = java.util.concurrent.CountDownLatch.new(1)
        @first_request = nil

        @t = java.lang.Thread.new(
          proc do
            begin
              @server = WEBrick::HTTPServer.new :Port => 0, :DocumentRoot => ".",
                       :Logger => Cabin::Channel.get, # silence WEBrick logging
                       :StartCallback => Proc.new { queue.push("started") }
              @port = @server.config[:Port]
              @server.mount_proc '/' do |req, res|
                res.body = '''
                {
                    "name": "ce7ccfb438e8",
                    "cluster_name": "docker-cluster",
                    "cluster_uuid": "DyR1hN03QvuCWXRy3jtb0g",
                    "version": {
                        "number": "7.13.1",
                        "build_flavor": "default",
                        "build_type": "docker",
                        "build_hash": "9a7758028e4ea59bcab41c12004603c5a7dd84a9",
                        "build_date": "2021-05-28T17:40:59.346932922Z",
                        "build_snapshot": false,
                        "lucene_version": "8.8.2",
                        "minimum_wire_compatibility_version": "6.8.0",
                        "minimum_index_compatibility_version": "6.0.0-beta1"
                    },
                    "tagline": "You Know, for Search"
                }
                '''
                res.status = 200
                res['Content-Type'] = 'application/json'
                @first_request = req
                @first_req_waiter.countDown()
              end

              @server.mount_proc '/logstash_unit_test/_search' do |req, res|
                res.body = '''
                {
                  "took" : 1,
                  "timed_out" : false,
                  "_shards" : {
                    "total" : 1,
                    "successful" : 1,
                    "skipped" : 0,
                    "failed" : 0
                  },
                  "hits" : {
                    "total" : {
                      "value" : 10000,
                      "relation" : "gte"
                    },
                    "max_score" : 1.0,
                    "hits" : [
                      {
                        "_index" : "test_bulk_index_2",
                        "_type" : "_doc",
                        "_id" : "sHe6A3wBesqF7ydicQvG",
                        "_score" : 1.0,
                        "_source" : {
                          "@timestamp" : "2021-09-20T15:02:02.557Z",
                          "message" : "{\"name\": \"Andrea\"}",
                          "@version" : "1",
                          "host" : "kalispera",
                          "sequence" : 5
                        }
                      }
                    ]
                  }
                }
                '''
                res.status = 200
                res['Content-Type'] = 'application/json'
                @first_request = req
                @first_req_waiter.countDown()
              end

              @server.start
            rescue => e
              warn "ERROR in webserver thread #{e.inspect}\n  #{e.backtrace.join("\n  ")}"
              # ignore
            end
          end
        )
        @t.daemon = true
        @t.start
        queue.pop # blocks until the server is up
      end

      def stop
        @server.shutdown
      end

      def wait_receive_request
        @first_req_waiter.await(2, java.util.concurrent.TimeUnit::SECONDS)
        @first_request
      end
    end

    describe "'user-agent' header" do
      let!(:webserver) { StoppableServer.new } # webserver must be started before the call, so no lazy "let"

      after :each do
        webserver.stop
      end

      it "server should be started" do
        require 'net/http'
        response = nil
        Net::HTTP.start('localhost', webserver.port) {|http|
          response = http.request_get('/')
        }
        expect(response.code.to_i).to eq(200)
      end

      context "used by plugin" do
        let(:config) do
          {
            "hosts" => ["localhost:#{webserver.port}"],
            "query" => '{ "query": { "match": { "statuscode": 200 } }, "sort": [ "_doc" ] }',
            "index" => "logstash_unit_test"
          }
        end
        let(:plugin) { described_class.new(config) }
        let(:event)  { LogStash::Event.new({}) }

        # elasticsearch-ruby 7.17.9 initialize two user agent headers, `user-agent` and `User-Agent`
        # hence, fail this header size test case
        xit "client should sent the expect user-agent" do
          plugin.register

          queue = []
          plugin.run(queue)

          request = webserver.wait_receive_request

          expect(request.header['user-agent'].size).to eq(1)
          expect(request.header['user-agent'][0]).to match(/logstash\/\d*\.\d*\.\d* \(OS=.*; JVM=.*\) logstash-input-elasticsearch\/\d*\.\d*\.\d*/)
        end
      end
    end

    shared_examples 'configurable timeout' do |config_name, manticore_transport_option|
      let(:config_value) { fail NotImplementedError }
      let(:config) { super().merge(config_name => config_value) }
      {
          :string   => 'banana',
          :negative => -123,
          :zero     => 0,
      }.each do |value_desc, value|
        let(:config_value) { value }
        context "with an invalid #{value_desc} value" do
          it 'prevents instantiation with a helpful message' do
            expect(described_class.logger).to receive(:error).with(/Expected positive whole number/)
            expect { described_class.new(config) }.to raise_error(LogStash::ConfigurationError)
          end
        end
      end

      context 'with a valid value' do
        let(:config_value) { 17 }

        it "instantiates the elasticsearch client with the timeout value set via #{manticore_transport_option} in the transport options" do
          expect(Elasticsearch::Client).to receive(:new) do |new_elasticsearch_client_params|
            # We rely on Manticore-specific transport options, fail early if we are using a different
            # transport or are allowing the client to determine its own transport class.
            expect(new_elasticsearch_client_params).to include(:transport_class)
            expect(new_elasticsearch_client_params[:transport_class].name).to match(/\bManticore\b/)

            expect(new_elasticsearch_client_params).to include(:transport_options)
            transport_options = new_elasticsearch_client_params[:transport_options]
            expect(transport_options).to include(manticore_transport_option)
            expect(transport_options[manticore_transport_option]).to eq(config_value.to_i)
            mock_client = double("fake_client")
            allow(mock_client).to receive(:ping)
            allow(mock_client).to receive(:info).and_return(cluster_info)
            mock_client
          end

          plugin.register
        end

        after { plugin.do_stop }
      end
    end

    context 'connect_timeout_seconds' do
      include_examples('configurable timeout', 'connect_timeout_seconds', :connect_timeout)
    end
    context 'request_timeout_seconds' do
      include_examples('configurable timeout', 'request_timeout_seconds', :request_timeout)
    end
    context 'socket_timeout_seconds' do
      include_examples('configurable timeout', 'socket_timeout_seconds', :socket_timeout)
    end
  end

  context "when scheduling" do
    let(:config) do
      {
        "hosts" => ["localhost"],
        "query" => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }',
        "schedule" => "* * * * * * UTC" # every second
      }
    end

    before do
      plugin.register
    end

    it "should properly schedule" do
      begin
        expect(plugin.instance_variable_get(:@query_executor)).to receive(:do_run) {
          queue << LogStash::Event.new({})
        }.at_least(:twice)
        runner = Thread.start { plugin.run(queue) }
        expect(queue.pop).not_to be_nil
        cron_jobs = plugin.instance_variable_get(:@_scheduler).instance_variable_get(:@impl).jobs
        expect(cron_jobs[0].next_time - cron_jobs[0].last_time).to be <= 5.0
        expect(queue.pop).not_to be_nil
      ensure
        plugin.do_stop
        runner.join if runner
      end
    end
  end

  context "aggregations" do
    let(:index_name) { "rainbow" }
    let(:config) do
      {
        'hosts'         => ["localhost"],
        'query'         => '{ "query": {}, "size": 0, "aggs":{"total_count": { "value_count": { "field": "type" }}, "empty_count": { "sum": { "field": "_meta.empty_event" }}}}',
        'response_type' => 'aggregations',
        'size'          => 0,
        'index'         => index_name
      }
    end

    let(:mock_response) do
      {
        "took" => 27,
        "timed_out" => false,
        "_shards" => {
          "total" => 169,
          "successful" => 169,
          "skipped" => 0,
          "failed" => 0
        },
        "hits" => {
          "total" => 10,
          "max_score" => 1.0,
          "hits" => []
        },
        "aggregations" => {
          "total_counter" => {
            "value" => 10
          },
          "empty_counter" => {
            "value" => 5
          },
        }
      }
    end

    let(:client) { Elasticsearch::Client.new }
    before(:each) do
      expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
      expect(client).to receive(:ping)
    end

    before { plugin.register }

    it 'creates the events from the aggregations' do
      expect(client).to receive(:search).with(hash_including(:body => anything, :size => 0, :index => index_name)).and_return(mock_response)
      plugin.run queue
      event = queue.pop

      expect(event).to be_a(LogStash::Event)
      expect(event.get("[total_counter][value]")).to eql 10
      expect(event.get("[empty_counter][value]")).to eql 5
    end

    context "when there's an exception" do
      before(:each) do
        allow(client).to receive(:search).and_raise RuntimeError
      end
      it 'produces no events' do
        plugin.run queue
        expect(queue).to be_empty
      end
    end
  end

  context "retries" do
    let(:client) { Elasticsearch::Client.new }
    let(:config) do
      {
        "hosts" => ["localhost"],
        "query" => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }',
        "retries" => 1
      }
    end

    shared_examples "a retryable plugin" do
      it "retry and log error when all search request fail" do
        expect_any_instance_of(LogStash::Helpers::LoggableTry).to receive(:log_failure).with(instance_of(Manticore::UnknownException), instance_of(Integer), instance_of(String)).twice
        expect(client).to receive(:search).with(instance_of(Hash)).and_raise(Manticore::UnknownException).at_least(:twice)

        plugin.register

        expect{ plugin.run(queue) }.not_to raise_error
      end

      it "retry successfully when search request fail for one time" do
        expect_any_instance_of(LogStash::Helpers::LoggableTry).to receive(:log_failure).with(instance_of(Manticore::UnknownException), 1, instance_of(String))
        expect(client).to receive(:search).with(instance_of(Hash)).once.and_raise(Manticore::UnknownException)
        expect(client).to receive(:search).with(instance_of(Hash)).once.and_return(search_response)

        plugin.register

        expect{ plugin.run(queue) }.not_to raise_error
      end
    end

    describe "scroll" do
      let(:search_response) do
        {
          "_scroll_id" => "cXVlcnlUaGVuRmV0Y2g",
          "took" => 27,
          "timed_out" => false,
          "_shards" => {
            "total" => 169,
            "successful" => 169,
            "failed" => 0
          },
          "hits" => {
            "total" => 1,
            "max_score" => 1.0,
            "hits" => [ {
                          "_index" => "logstash-2014.10.12",
                          "_type" => "logs",
                          "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
                          "_score" => 1.0,
                          "_source" => { "message" => ["ohayo"] }
                        } ]
          }
        }
      end

      let(:empty_scroll_response) do
        {
          "_scroll_id" => "r453Wc1jh0caLJhSDg",
          "hits" => { "hits" => [] }
        }
      end

      before(:each) do
        allow(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
        allow(client).to receive(:scroll).with({ :body => { :scroll_id => "cXVlcnlUaGVuRmV0Y2g" }, :scroll=> "1m" }).and_return(empty_scroll_response)
        allow(client).to receive(:clear_scroll).and_return(nil)
        allow(client).to receive(:ping)
      end

      it_behaves_like "a retryable plugin"
    end

    describe "search_after" do
      let(:es_version) { "8.10.0" }
      let(:config) { super().merge({ "search_api" => "search_after" }) }

      let(:search_response) do
        {
          "took" => 27,
          "timed_out" => false,
          "_shards" => {
            "total" => 169,
            "successful" => 169,
            "failed" => 0
          },
          "hits" => {
            "total" => 1,
            "max_score" => 1.0,
            "hits" => [ ] # empty hits to break the loop
          }
        }
      end

      before(:each) do
        expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
        expect(client).to receive(:open_point_in_time).once.and_return({ "id" => "cXVlcnlUaGVuRmV0Y2g"})
        expect(client).to receive(:close_point_in_time).once.and_return(nil)
        expect(client).to receive(:ping)
      end

      it_behaves_like "a retryable plugin"
    end
  end

  # @note can be removed once we depends on elasticsearch gem >= 6.x
  def extract_transport(client) # on 7.x client.transport is a ES::Transport::Client
    client.transport.respond_to?(:transport) ? client.transport.transport : client.transport
  end

end
