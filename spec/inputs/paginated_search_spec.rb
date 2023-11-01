require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch/paginated_search"

describe "Paginated search" do
  let(:es_client) { double("Elasticsearch::Client") }
  let(:settings) { { "index" => "logs", "query" => "{ \"sort\": [ \"_doc\" ] }", "scroll" => "1m", "retries" => 0, "size" => 1000 } }
  let(:plugin) { double("LogStash::Inputs::Elasticsearch", params: settings, pipeline_id: "main", stop?: false) }
  let(:pit_id) { "08fsAwILcmVzaGFyZC0yZmIWdzFnbl" }

  describe "search after" do
    subject do
      LogStash::Inputs::Elasticsearch::SearchAfter.new(es_client, plugin)
    end

    describe "search options" do
      context "query without sort" do
        let(:settings) { super().merge({"query" => "{\"match_all\": {} }"}) }

        it "adds default sort" do
          options = subject.search_options(pit_id: pit_id)
          expect(options[:body][:sort]).to match({"_shard_doc": "asc"})
        end
      end

      context "customize settings" do
        let(:size) { 2 }
        let(:slices) { 4 }
        let(:settings) { super().merge({"slices" => slices, "size" => size}) }

        it "gives updated options" do
          slice_id = 1
          search_after = [0, 0]
          options = subject.search_options(pit_id: pit_id, slice_id: slice_id, search_after: search_after)
          expect(options[:size]).to match(size)
          expect(options[:body][:slice]).to match({:id => slice_id, :max => slices})
          expect(options[:body][:search_after]).to match(search_after)
        end
      end
    end

    describe "search" do
      let(:queue) { double("queue") }
      let(:doc1) do
        {
          "_index" => "logstash",
          "_type" => "logs",
          "_id" => "C5b2xLQwTZa76jBmHIbwHQ",
          "_score" => 1.0,
          "_source" => { "message" => ["Halloween"] },
          "sort" => [0, 0]
        }
      end
      let(:first_resp) do
        {
          "pit_id" => pit_id,
          "took" => 27,
          "timed_out" => false,
          "_shards" => {
            "total" => 2,
            "successful" => 2,
            "skipped" => 0,
            "failed" => 0
          },
          "hits" => {
            "total" => {
              "value" => 500,
              "relation" => "eq"
            },
            "hits" => [ doc1 ]
          }
        }
      end
      let(:last_resp) do
        {
          "pit_id" => pit_id,
          "took" => 27,
          "timed_out" => false,
          "_shards" => {
            "total" => 2,
            "successful" => 2,
            "skipped" => 0,
            "failed" => 0
          },
          "hits" => {
            "total" => {
              "value" => 500,
              "relation" => "eq"
            },
            "hits" => [ ] # empty hits to break the loop
          }
        }
      end

      context "happy case" do
        it "runs" do
          expect(es_client).to receive(:search).with(instance_of(Hash)).and_return(first_resp, last_resp)
          expect(plugin).to receive(:push_hit).with(doc1, queue).once
          subject.search(output_queue: queue, pit_id: pit_id)
        end
      end

      context "with exception" do
        it "closes pit" do
          expect(es_client).to receive(:open_point_in_time).once.and_return({ "id" => pit_id})
          expect(plugin).to receive(:push_hit).with(doc1, queue).once
          expect(es_client).to receive(:search).with(instance_of(Hash)).once.and_return(first_resp)
          expect(es_client).to receive(:search).with(instance_of(Hash)).once.and_raise(Manticore::UnknownException)
          expect(es_client).to receive(:close_point_in_time).with(any_args).once.and_return(nil)
          subject.retryable_search(queue)
        end
      end

      context "with slices" do
        let(:slices) { 2 }
        let(:settings) { super().merge({"slices" => slices}) }

        it "runs two slices" do
          expect(es_client).to receive(:open_point_in_time).once.and_return({ "id" => pit_id})
          expect(plugin).to receive(:push_hit).with(any_args).twice
          expect(Thread).to receive(:new).and_call_original.exactly(slices).times
          expect(es_client).to receive(:search).with(instance_of(Hash)).and_return(first_resp, last_resp, first_resp, last_resp)
          expect(es_client).to receive(:close_point_in_time).with(any_args).once.and_return(nil)
          subject.retryable_slice_search(queue)
        end
      end
    end
  end

end