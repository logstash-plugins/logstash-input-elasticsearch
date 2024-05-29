require 'fileutils'

module LogStash; module Inputs; class Elasticsearch
  class NoopCursorTracker
    include LogStash::Util::Loggable
    def checkpoint_cursor; end

    def converge_last_value; end

    def record_last_value(event); end

    def inject_cursor(query_json); return query_json; end
  end

  class CursorTracker
    include LogStash::Util::Loggable

    attr_reader :last_value

    def initialize(last_run_metadata_path:, tracking_field:, tracking_field_seed:)
      @last_run_metadata_path = last_run_metadata_path
      @last_run_metadata_path ||= ::File.join(LogStash::SETTINGS.get_value("path.data"), "plugins", "inputs", "elasticsearch", "last_run_value")
      FileUtils.mkdir_p ::File.dirname(@last_run_metadata_path)
      @last_value_hashmap = Java::java.util.concurrent.ConcurrentHashMap.new
      @last_value = IO.read(@last_run_metadata_path) rescue nil || tracking_field_seed
      @tracking_field = tracking_field
      logger.info "Starting value for cursor field \"#{@tracking_field}\": #{@last_value}"
    end

    def checkpoint_cursor
      converge_last_value
      IO.write(@last_run_metadata_path, @last_value)
      @last_value_hashmap.clear
    end

    def converge_last_value
      return if @last_value_hashmap.empty?
      # TODO this implicitly assumes that the way to converge the value among slices is to pick the highest and we can't assume that
      new_last_value = @last_value_hashmap.reduceValues(1, lambda { |v1, v2| Time.parse(v1) < Time.parse(v2) ? v2 : v1 })
      return if new_last_value == @last_value
      @last_value = new_last_value
      logger.info "New cursor value for field \"#{@tracking_field}\" is: #{new_last_value}"
    end

    def record_last_value(event)
      value = event.get(@tracking_field)
      logger.trace? && logger.trace("storing last_value if #{@tracking_field} for #{Thread.current.object_id}: #{value}")
      @last_value_hashmap.put(Thread.current.object_id, value)
    end

    def inject_cursor(query_json)
      query_json.gsub(":last_value", @last_value)
    end
  end
end; end; end
