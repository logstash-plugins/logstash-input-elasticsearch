# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/inputs/elasticsearch/cursor_tracker"

describe LogStash::Inputs::Elasticsearch::CursorTracker do

  let(:last_run_metadata_path) { Tempfile.new('cursor_tracker_testing').path }
  let(:tracking_field_seed) { "1980-01-01T23:59:59.999999999Z" }
  let(:options) do
    {
      :last_run_metadata_path => last_run_metadata_path,
      :tracking_field => "my_field",
      :tracking_field_seed => tracking_field_seed
    }
  end

  subject { described_class.new(**options) }

  it "creating a class works" do
    expect(subject).to be_a described_class
  end

  describe "checkpoint_cursor" do
    before(:each) do
      [
        Thread.new(subject) {|subject| subject.record_last_value(LogStash::Event.new("my_field" => "2025-01-03T23:59:59.999999999Z")) },
        Thread.new(subject) {|subject| subject.record_last_value(LogStash::Event.new("my_field" => "2025-01-01T23:59:59.999999999Z")) },
        Thread.new(subject) {|subject| subject.record_last_value(LogStash::Event.new("my_field" => "2025-01-02T23:59:59.999999999Z")) },
      ].each(&:join)
    end
    context "when doing intermediate checkpoint" do
      before(:each) { subject.checkpoint_cursor(intermediate: true) }
      it "persists the smallest value" do
        expect(IO.read(last_run_metadata_path)).to eq("2025-01-01T23:59:59.999999999Z")
      end
    end
    context "when doing non-intermediate checkpoint" do
      before(:each) { subject.checkpoint_cursor(intermediate: false) }
      it "persists the largest value" do
        expect(IO.read(last_run_metadata_path)).to eq("2025-01-03T23:59:59.999999999Z")
      end
    end
  end

  describe "inject_cursor" do
    let(:new_value) { "2025-01-03T23:59:59.999999999Z" }
    let(:fake_now) { "2026-09-19T23:59:59.999999999Z" }

    let(:query) do
      %q[
      { "query": { "range": { "event.ingested": { "gt": :last_value, "lt": :present}}}, "sort": [ { "event.ingested": {"order": "asc", "format": "strict_date_optional_time_nanos", "numeric_type" : "date_nanos" } } ] }
      ]
    end

    before(:each) do
      subject.record_last_value(LogStash::Event.new("my_field" => new_value))
      subject.checkpoint_cursor(intermediate: false)
      allow(subject).to receive(:now_in_nanos).and_return(fake_now)
    end

    it "injects the value of the cursor into json query if it contains :last_value" do
      expect(subject.inject_cursor(query)).to match(/#{new_value}/)
    end

    it "injects current time into json query if it contains :present" do
      expect(subject.inject_cursor(query)).to match(/#{fake_now}/)
    end
  end
end
