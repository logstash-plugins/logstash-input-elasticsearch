require 'fileutils'

module LogStash; module Inputs; class Elasticsearch
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
      new_last_value = @last_value_hashmap.reduceValues(1000, lambda { |v1, v2| Java::java.time.Instant.parse(v1).isBefore(Java::java.time.Instant.parse(v2)) ? v2 : v1 })
      logger.trace? && logger.trace("converge_last_value: got #{@last_value_hashmap.values.inspect}. won: #{new_last_value}")
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
      result = query_json.gsub(":last_value", @last_value.to_s).gsub(":present", Java::java.time.Instant.now.minusSeconds(30).to_s)
      logger.debug("inject_cursor: injected values for ':last_value' and ':present'", :query => result)
      result
    end
  end
end; end; end
