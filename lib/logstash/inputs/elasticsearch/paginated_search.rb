# frozen_string_literal: true

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

          @search_options = {
            :index => @index,
            :scroll => @scroll,
            :size => @size
          }

          @plugin = plugin
        end

        def search(output_queue, slice_id=nil)
          raise NotImplementedError
        end
      end

      class Scroll < PaginatedSearch
        attr_reader :scroll_id

        def prepare_search_options(slice_id)
          query = @query
          query = @query.merge('slice' => { 'id' => slice_id, 'max' => @slices}) unless slice_id.nil?
          @search_options.merge(:body => LogStash::Json.dump(query) )
        end

        def initial_search(slice_id)
          options = prepare_search_options(slice_id)
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

            logger.info("Search start", log_hash)
            has_hits, scroll_id = process_page(output_queue) { initial_search(slice_id) }

            while has_hits && scroll_id && !@plugin.stop?
              logger.debug("Search progress", log_hash)
              has_hits, scroll_id = process_page(output_queue) { next_page(scroll_id) }
            end

            logger.info("Search completed", log_hash)
          ensure
            clear(scroll_id)
          end
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
