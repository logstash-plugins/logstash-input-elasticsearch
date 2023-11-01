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

        def do_run(output_queue)
          # if configured to run a single slice, don't bother spinning up threads
          return retryable_search(output_queue) if @slices.nil? || @slices <= 1

          retryable_slice_search(output_queue)
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

        def retryable_search(output_queue)
          raise NotImplementedError
        end

        def retryable_slice_search(output_queue)
          raise NotImplementedError
        end
      end

      class Scroll < PaginatedSearch
        SCROLL_JOB = "run scroll"

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

        def retryable_search(output_queue, slice_id=nil)
          retryable(SCROLL_JOB) do
            search(output_queue, slice_id)
          end
        end

        def retryable_slice_search(output_queue)
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
        PIT_JOB = "create point in time"
        SEARCH_AFTER_JOB = "run search after"

        def create_pit
          logger.debug("create point in time")
          r = @client.open_point_in_time(index: @index, keep_alive: @scroll)
          r['id']
        end

        def search_options(pit_id: , search_after: nil, slice_id: nil)
          body = @query.merge({
                                :pit => {
                                  :id => pit_id,
                                  :keep_alive => @scroll
                                }
                              })
          body = body.merge(:search_after => search_after) unless search_after.nil?
          body = body.merge(:slice => {:id => slice_id, :max => @slices}) unless slice_id.nil?
          {
            :size => @size,
            :body => body
          }
        end

        def next_page(pit_id: , search_after: nil, slice_id: nil)
          options = search_options(pit_id: pit_id, search_after: search_after, slice_id: slice_id)
          @client.search(options)
        end

        def process_page(output_queue)
          r = yield
          r['hits']['hits'].each { |hit| @plugin.push_hit(hit, output_queue) }
          search_after = r['hits']['hits'][-1]['sort'] rescue nil
          [ r['hits']['hits'].any?, search_after ]
        end

        def with_pit
          begin
            pit_id = retryable(PIT_JOB) { create_pit }
            yield pit_id if pit_id.is_a?(String)
          ensure
            clear(pit_id)
          end
        end

        def search(output_queue:, slice_id: nil, pit_id:)
          log_hash = {}
          log_hash = log_hash.merge({ slice_id: slice_id, slices: @slices }) unless slice_id.nil?
          logger.info("Query start", log_hash)

          has_hits = true
          search_after = nil

          while has_hits && !@plugin.stop?
            logger.debug("Query progress", log_hash)
            has_hits, search_after = process_page(output_queue) do
              next_page(pit_id: pit_id, search_after: search_after, slice_id: slice_id)
            end
          end

          logger.info("Query completed", log_hash)
        end

        def retryable_search(output_queue)
          with_pit do |pit_id|
            retryable(SEARCH_AFTER_JOB) do
              search(output_queue: output_queue, pit_id: pit_id)
            end
          end
        end

        def retryable_slice_search(output_queue)
          with_pit do |pit_id|
            @slices.times.map do |slice_id|
              Thread.new do
                LogStash::Util::set_thread_name("[#{@pipeline_id}]|input|elasticsearch|slice_#{slice_id}")
                retryable(SEARCH_AFTER_JOB) do
                  search(output_queue: output_queue, slice_id: slice_id, pit_id: pit_id)
                end
              end
            end.map(&:join)
          end

          logger.trace("#{@slices} slices completed")
        end

        def clear(pit_id)
          logger.debug("close point in time")
          @client.close_point_in_time(:body => {:id => pit_id} ) if pit_id
        rescue => e
          logger.warn("Ignoring close_point_in_time exception", message: e.message, exception: e.class)
        end
      end

    end
  end
end
