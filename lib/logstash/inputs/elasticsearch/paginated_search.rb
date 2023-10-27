# frozen_string_literal: true
require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class PaginatedSearch
        include LogStash::Util::Loggable

        def initialize(client, plugin)
          @client = client
          @plugin_params = plugin.params

          @index = @plugin_params["index"]
          @query = LogStash::Json.load(@plugin_params["query"])
          @scroll = @plugin_params["scroll"]
          @size = @plugin_params["size"]
          @slices = @plugin_params["slices"]
          @retries = @plugin_params["retries"]

          @plugin = plugin
          @pipeline_id = plugin.pipeline_id
        end

        JOB_NAME = "run query"
        def do_run(output_queue)
          # if configured to run a single slice, don't bother spinning up threads
          return retryable_search(output_queue) if @slices.nil? || @slices <= 1

          slice_search(output_queue)
        end

        def retryable_search(output_queue, slice_id=nil)
          retryable(JOB_NAME) do
            r = search(output_queue, slice_id)
            r
          end
        end

        def retryable(job_name, &block)
          begin
            stud_try = ::LogStash::Helpers::LoggableTry.new(logger, job_name)
            stud_try.try((@retries + 1).times) { yield }
          rescue => e
            error_details = {:message => e.message, :cause => e.cause}
            error_details[:backtrace] = e.backtrace if logger.debug?
            logger.error("Tried #{job_name} unsuccessfully", error_details)
          end
        end

        def search(output_queue, slice_id=nil)
          raise NotImplementedError
        end

        def slice_search(output_queue)
          raise NotImplementedError
        end
      end

      class Scroll < PaginatedSearch
        def search_options(slice_id)
          query = @query
          query = @query.merge('slice' => { 'id' => slice_id, 'max' => @slices}) unless slice_id.nil?
          {
            :index => @index,
            :scroll => @scroll,
            :size => @size,
            :body => LogStash::Json.dump(query)
          }
        end

        def initial_search(slice_id)
          options = search_options(slice_id)
          @client.search(options)
        end

        def next_page(scroll_id)
          @client.scroll(:body => { :scroll_id => scroll_id }, :scroll => @scroll)
        end

        def process_page(output_queue)
          r = yield
          r['hits']['hits'].each { |hit| @plugin.push_hit(hit, output_queue) }
          [r['hits']['hits'].any?, r['_scroll_id']]
        end

        def search(output_queue, slice_id=nil)
          begin
            log_hash = {}
            log_hash = log_hash.merge({ slice_id: slice_id, slices: @slices }) unless slice_id.nil?

            logger.info("Query start", log_hash)
            has_hits, scroll_id = process_page(output_queue) { initial_search(slice_id) }

            while has_hits && scroll_id && !@plugin.stop?
              logger.debug("Query progress", log_hash)
              has_hits, scroll_id = process_page(output_queue) { next_page(scroll_id) }
            end

            logger.info("Query completed", log_hash)
          ensure
            clear(scroll_id)
          end
        end

        def slice_search(output_queue)
          logger.warn("managed slices for query is very large (#{@slices}); consider reducing") if @slices > 8

          @slices.times.map do |slice_id|
            Thread.new do
              LogStash::Util::set_thread_name("[#{@pipeline_id}]|input|elasticsearch|slice_#{slice_id}")
              retryable_search(output_queue, slice_id)
            end
          end.map(&:join)

          logger.trace("#{@slices} slices completed")
        end

        def clear(scroll_id)
          @client.clear_scroll(:body => { :scroll_id => scroll_id }) if scroll_id
        rescue => e
          # ignore & log any clear_scroll errors
          logger.warn("Ignoring clear_scroll exception", message: e.message, exception: e.class)
        end
      end

      class SearchAfter < PaginatedSearch

      end

    end
  end
end
