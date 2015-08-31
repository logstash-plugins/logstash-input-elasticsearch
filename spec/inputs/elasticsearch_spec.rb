# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"

describe LogStash::Inputs::Elasticsearch do
  it "should retrieve json event from elasticseach" do
    config = %q[
      input {
        elasticsearch {
          hosts => ["localhost"]
          scan => false
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
    expect(client).to receive(:scroll).with({ :body => "cXVlcnlUaGVuRmV0Y2g", :scroll=> "1m" }).and_return(scroll_reponse)

    event = input(config) do |pipeline, queue|
      queue.pop
    end

    insist { event }.is_a?(LogStash::Event)
    insist { event["message"] } == [ "ohayo" ]
  end

  it "should retrieve json event from elasticseach with scan" do
    config = %q[
      input {
        elasticsearch {
          hosts => ["localhost"]
          scan => true
          query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
        }
      }
    ]

    scan_response = {
      "_scroll_id" => "DcrY3G1xff6SB",
    }

    scroll_responses = [
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
      },
      {
        "_scroll_id" => "r453Wc1jh0caLJhSDg",
        "hits" => { "hits" => [] }
      }
    ]

    client = Elasticsearch::Client.new
    expect(Elasticsearch::Client).to receive(:new).with(any_args).and_return(client)
    expect(client).to receive(:search).with(any_args).and_return(scan_response)
    expect(client).to receive(:scroll).with({ :body => "DcrY3G1xff6SB", :scroll => "1m" }).and_return(scroll_responses.first)
    expect(client).to receive(:scroll).with({ :body=> "cXVlcnlUaGVuRmV0Y2g", :scroll => "1m" }).and_return(scroll_responses.last)

    event = input(config) do |pipeline, queue|
      queue.pop
    end

    insist { event }.is_a?(LogStash::Event)
    insist { event["message"] } == [ "ohayo" ]
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
      allow(client).to receive(:scroll).with({ :body => "cXVlcnlUaGVuRmV0Y2g", :scroll => "1m" }).and_return(scroll_reponse)
    end

    context 'when defining docinfo' do
      let(:config_metadata) do
        %q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                scan => false
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
                scan => false
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => '#{metadata_field}'
              }
            }
        ]

        event = input(config_metadata_with_hash) do |pipeline, queue|
          queue.pop
        end

        expect(event[metadata_field]["_index"]).to eq('logstash-2014.10.12')
        expect(event[metadata_field]["_type"]).to eq('logs')
        expect(event[metadata_field]["_id"]).to eq('C5b2xLQwTZa76jBmHIbwHQ')
        expect(event[metadata_field]["awesome"]).to eq("logstash")
      end
      
      it 'thows an exception if the `docinfo_target` exist but is not of type hash' do
        metadata_field = 'metadata_with_string'

        config_metadata_with_string = %Q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                scan => false
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => '#{metadata_field}'
              }
            }
        ]

        pipeline = LogStash::Pipeline.new(config_metadata_with_string)
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

        expect(event["[@metadata][_index]"]).to eq('logstash-2014.10.12')
        expect(event["[@metadata][_type]"]).to eq('logs')
        expect(event["[@metadata][_id]"]).to eq('C5b2xLQwTZa76jBmHIbwHQ')
      end

      it 'should move the document information to the specified field' do
        config = %q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                scan => false
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_target => 'meta'
              }
            }
        ]
        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event["[meta][_index]"]).to eq('logstash-2014.10.12')
        expect(event["[meta][_type]"]).to eq('logs')
        expect(event["[meta][_id]"]).to eq('C5b2xLQwTZa76jBmHIbwHQ')
      end

      it "should allow to specify which fields from the document info to save to the @metadata field" do
        fields = ["_index"]
        config = %Q[
            input {
              elasticsearch {
                hosts => ["localhost"]
                scan => false
                query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
                docinfo => true
                docinfo_fields => #{fields}
              }
            }]

        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event["@metadata"].keys).to eq(fields)
        expect(event["[@metadata][_type]"]).to eq(nil)
        expect(event["[@metadata][_index]"]).to eq('logstash-2014.10.12')
        expect(event["[@metadata][_id]"]).to eq(nil)
      end
    end

    context "when not defining the docinfo" do
      it 'should keep the document information in the root of the event' do
        config = %q[
          input {
            elasticsearch {
              hosts => ["localhost"]
              scan => false
              query => '{ "query": { "match": { "city_name": "Okinawa" } }, "fields": ["message"] }'
            }
          }
        ]
        event = input(config) do |pipeline, queue|
          queue.pop
        end

        expect(event["[@metadata][_index]"]).to eq(nil)
        expect(event["[@metadata][_type]"]).to eq(nil)
        expect(event["[@metadata][_id]"]).to eq(nil)
      end
    end
  end
end
