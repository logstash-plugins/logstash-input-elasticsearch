require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"

describe "inputs/elasticsearch" do

  it "should retrieve json event from elasticseach" do

    config = %q[
      input {
        elasticsearch {
          hosts => ["node01"]
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
          "fields" => {"message" => ["ohayo"] }
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
    expect(client).to receive(:scroll).with({:body=>"cXVlcnlUaGVuRmV0Y2g", :scroll=>"1m"}).and_return(scroll_reponse)

    pipeline = LogStash::Pipeline.new(config)
    queue = Queue.new
    pipeline.instance_eval do
      @output_func = lambda { |event| queue << event }
    end
    pipeline_thread = Thread.new { pipeline.run }
    event = queue.pop

    insist { event["fields"]["message"] } == [ "ohayo" ]

    pipeline_thread.join
  end

  it "should retrieve json event from elasticseach with scan" do

    config = %q[
      input {
        elasticsearch {
          hosts => ["node01"]
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
            "fields" => {"message" => ["ohayo"] }
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
    expect(client).to receive(:scroll).with({:body=>"DcrY3G1xff6SB", :scroll=>"1m"}).and_return(scroll_responses.first)
    expect(client).to receive(:scroll).with({:body=>"cXVlcnlUaGVuRmV0Y2g", :scroll=>"1m"}).and_return(scroll_responses.last)

    pipeline = LogStash::Pipeline.new(config)
    queue = Queue.new
    pipeline.instance_eval do
      @output_func = lambda { |event| queue << event }
    end
    pipeline_thread = Thread.new { pipeline.run }
    event = queue.pop

    insist { event["fields"]["message"] } == [ "ohayo" ]

    pipeline_thread.join
  end
end
