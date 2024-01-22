require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class Aggregation
        include LogStash::Util::Loggable

        def initialize(client, plugin)
          @client = client
          @plugin_params = plugin.params

          @scroll = @plugin_params["scroll"]
          @size = @plugin_params["size"]
          @index = @plugin_params["index"]
          @query = @plugin_params["query"]
          @agg_options = {
            :index => @index,
            :size  => @size
          }.merge(:body => @query)

          @plugin = plugin
        end

        def do_run(output_queue)
          logger.info("Aggregation starting")
          r = @client.search(@agg_options)
          @plugin.push_hit r, output_queue, 'aggregations'
        end
      end
    end
  end
end
