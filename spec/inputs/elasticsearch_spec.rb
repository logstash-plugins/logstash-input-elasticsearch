# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"
require "timecop"
require "stud/temporary"
require "time"
require "date"

describe LogStash::Inputs::Elasticsearch do

  let(:plugin) { LogStash::Inputs::Elasticsearch.new(config) }
  let(:queue) { Queue.new }

  it_behaves_like "an interruptible input plugin" do
    let(:esclient) { double("elasticsearch-client") }
    let(:config) do
      {
        "schedule" => "* * * * * UTC"
      }
    end

    before :each do
      allow(Elasticsearch::Client).to receive(:new).and_return(esclient)
      hit = {
        "_index" => "logstash-2014.10.12",
        "_type" => "logs",
        "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
        "_score" => 1.0,
        "_source" => { "message" => ["ohayo"] }
      }
      allow(esclient).to receive(:search) { { "hits" => { "hits" => [hit] } } }
      allow(esclient).to receive(:scroll) { { "hits" => { "hits" => [hit] } } }
    end
  end

  it "should retrieve json event from elasticseach" do
    config = %q[
      input {
        elasticsearch {
          hosts => ["localhost"]
          query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
        }
      }
    ]

    response = {
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

    scroll_reponse = {
      "_scroll_id" => "r453Wc1jh0caLJhSDg",
      "hits" => { "hits" => [] }
    }

    client = Elasticsearch::Client.new
    expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
    expect(client).to receive(:search).with(any_args).and_return(response)
    expect(client).to receive(:scroll).with({ :body => { :scroll_id => "cXVlcnlUaGVuRmV0Y2g" }, :scroll=> "1m" }).and_return(scroll_reponse)

    event = input(config) do |pipeline, queue|
      queue.pop
    end

    insist { event }.is_a?(LogStash::Event)
    insist { event.get("message") } == [ "ohayo" ]
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
      it 'runs just one slice' do
        expect(plugin).to receive(:do_run_slice).with(duck_type(:<<))
        expect(Thread).to_not receive(:new)

        plugin.register
        plugin.run([])
      end
    end

    context 'without slices directive' do
      let(:config) { super().except('slices') }
      it 'runs just one slice' do
        expect(plugin).to receive(:do_run_slice).with(duck_type(:<<))
        expect(Thread).to_not receive(:new)

        plugin.register
        plugin.run([])
      end
    end

    2.upto(8) do |slice_count|
      context "with `slices => #{slice_count}`" do
        let(:slices) { slice_count }
        it "runs #{slice_count} independent slices" do
          expect(Thread).to receive(:new).and_call_original.exactly(slice_count).times
          slice_count.times do |slice_id|
            expect(plugin).to receive(:do_run_slice).with(duck_type(:<<), slice_id)
          end

          plugin.register
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

      let(:client) { Elasticsearch::Client.new }

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

      before(:each) do
        expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
        plugin.register

        # SLICE0 is a three-page scroll in which the last page is empty
        slice0_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 0, 'max' => 2}))
        expect(client).to receive(:search).with(hash_including(:body => slice0_query)).and_return(slice0_response0)
        expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll1 })).and_return(slice0_response1)
        expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice0_scroll2 })).and_return(slice0_response2)

        # SLICE1 is a two-page scroll in which the last page has no next scroll id
        slice1_query = LogStash::Json.dump(query.merge('slice' => { 'id' => 1, 'max' => 2}))
        expect(client).to receive(:search).with(hash_including(:body => slice1_query)).and_return(slice1_response0)
        expect(client).to receive(:scroll).with(hash_including(:body => { :scroll_id => slice1_scroll1 })).and_return(slice1_response1)

        synchronize_method!(plugin, :scroll_request)
        synchronize_method!(plugin, :search_request)
      end

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

      it 'emits the hitson the second page of the second slice' do
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
    end

    context 'when defining docinfo' do
      let(:config_metadata) do
        %q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
              }
            }
        ]
      end

      it 'merges the values if the `docinfo_target` already exist in the `_source` document' do
        metadata_field = 'metadata_with_hash'

        config_metadata_with_hash = %Q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => '#{metadata_field}'
              }
            }
        ]

        event = input(config_metadata_with_hash) do |pipeline, queue|
          queue.pop
        end

        expect(event.get("[#{metadata_field}][_index]")).to eq('logstash-2014.10.12')
        expect(event.get("[#{metadata_field}][_type]")).to eq('logs')
        expect(event.get("[#{metadata_field}][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
        expect(event.get("[#{metadata_field}][awesome]")).to eq("logstash")
      end

      it 'thows an exception if the `docinfo_target` exist but is not of type hash' do
        metadata_field = 'metadata_with_string'

        config_metadata_with_string = %Q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => '#{metadata_field}'
              }
            }
        ]

        pipeline = new_pipeline_from_string(config_metadata_with_string)
        queue = Queue.new
        pipeline.instance_eval do
          @output_func = lambda { |event| queue << event }
        end

        expect { pipeline.run }.to raise_error(Exception, /incompatible event/)
      end

      it "should move the document info to the @metadata field" do
        event = input(config_metadata) do |pipeline, queue|
          queue.pop
        end

        expect(event.get("[@metadata][_index]")).to eq('logstash-2014.10.12')
        expect(event.get("[@metadata][_type]")).to eq('logs')
        expect(event.get("[@metadata][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
      end

      it 'should move the document information to the specified field' do
        config = %q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => 'meta'
              }
            }
        ]
        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event.get("[meta][_index]")).to eq('logstash-2014.10.12')
        expect(event.get("[meta][_type]")).to eq('logs')
        expect(event.get("[meta][_id]")).to eq('C5b2xLQwTZa76jBmHIbwHQ')
      end

      it "should allow to specify which fields from the document info to save to the @metadata field" do
        fields = ["_index"]
        config = %Q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_fields => #{fields}
              }
            }]

        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event.get("@metadata").keys).to eq(fields)
        expect(event.get("[@metadata][_type]")).to eq(nil)
        expect(event.get("[@metadata][_index]")).to eq('logstash-2014.10.12')
        expect(event.get("[@metadata][_id]")).to eq(nil)
      end

      it 'should be able to reference metadata fields in `add_field` decorations' do
        config = %q[
          input {
            elasticsearch {
              hosts => ["localhost"]
              query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
              docinfo => true
              add_field => {
                'identifier' => "foo:%{[@metadata][_type]}:%{[@metadata][_id]}"
              }
            }
          }
        ]

        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event.get('identifier')).to eq('foo:logs:C5b2xLQwTZa76jBmHIbwHQ')
      end
    end

    context "when not defining the docinfo" do
      it 'should keep the document information in the root of the event' do
        config = %q[
          input {
            elasticsearch {
              hosts => ["localhost"]
              query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
            }
          }
        ]
        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event.get("[@metadata][_index]")).to eq(nil)
        expect(event.get("[@metadata][_type]")).to eq(nil)
        expect(event.get("[@metadata][_id]")).to eq(nil)
      end
    end
  end

  context "when scheduling" do
    let(:config) do
      {
        "hosts" => ["localhost"],
        "query" => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }',
        "schedule" => "* * * * * UTC"
      }
    end

    response = {
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

    scroll_reponse = {
      "_scroll_id" => "r453Wc1jh0caLJhSDg",
      "hits" => { "hits" => [] }
    }

    before do
      plugin.register
    end

    it "should properly schedule" do

      Timecop.travel(Time.new(2000))
      Timecop.scale(60)
      runner = Thread.new do
        expect(plugin).to receive(:do_run) {
          queue << LogStash::Event.new({})
        }.at_least(:twice)

        plugin.run(queue)
      end
      sleep 3
      plugin.stop
      runner.kill
      runner.join
      expect(queue.size).to eq(2)
      Timecop.return
    end

  end

end
