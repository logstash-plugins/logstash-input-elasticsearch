require 'fileutils'

module LogStash; module Inputs; class Elasticsearch
  class CursorTracker
    include LogStash::Util::Loggable

    attr_reader :last_value

    def initialize(last_run_metadata_path:, tracking_field:, tracking_field_seed:)
      @last_run_metadata_path = last_run_metadata_path
      @last_value_hashmap = Java::java.util.concurrent.ConcurrentHashMap.new
      @last_value = IO.read(@last_run_metadata_path) rescue nil || tracking_field_seed
      @tracking_field = tracking_field
      logger.info "Starting value for cursor field \"#{@tracking_field}\": #{@last_value}"
      @mutex = Mutex.new
    end

    def checkpoint_cursor(intermediate: true)
      @mutex.synchronize do
        if intermediate
          # in intermediate checkpoints pick the smallest
          converge_last_value {|v1, v2| v1 < v2 ? v1 : v2}
        else
          # in the last search of a PIT choose the largest
          converge_last_value {|v1, v2| v1 > v2 ? v1 : v2}
          @last_value_hashmap.clear
        end
        IO.write(@last_run_metadata_path, @last_value)
      end
    end

    def converge_last_value(&block)
      return if @last_value_hashmap.empty?
      new_last_value = @last_value_hashmap.reduceValues(1000, &block)
      logger.debug? && logger.debug("converge_last_value: got #{@last_value_hashmap.values.inspect}. won: #{new_last_value}")
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
      # ":present" means "now - 30s" to avoid grabbing partially visible data in the PIT
      result = query_json.gsub(":last_value", @last_value.to_s).gsub(":present", now_minus_30s)
      logger.debug("inject_cursor: injected values for ':last_value' and ':present'", :query => result)
      result
    end

    def now_minus_30s
      Java::java.time.Instant.now.minusSeconds(30).to_s
    end
  end
end; end; end
