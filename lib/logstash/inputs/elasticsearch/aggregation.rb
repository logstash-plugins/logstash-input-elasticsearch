require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class Aggregation
        include LogStash::Util::Loggable

        AGGREGATION_JOB = "aggregation"

        def initialize(client, plugin)
          @client = client
          @plugin_params = plugin.params

          @index = @plugin_params["index"]
          @size = @plugin_params["size"]
          @retries = @plugin_params["retries"]
          @plugin = plugin
        end

        def retryable(job_name, &block)
          stud_try = ::LogStash::Helpers::LoggableTry.new(logger, job_name)
          stud_try.try((@retries + 1).times) { yield }
        rescue => e
          error_details = {:message => e.message, :cause => e.cause}
          error_details[:backtrace] = e.backtrace if logger.debug?
          logger.error("Tried #{job_name} unsuccessfully", error_details)
          false
        end

        def aggregation_options(query_object)
          {
            :index => @index,
            :size => 0,
            :body => query_object
          }
        end

        def do_run(output_queue, query_object)
          logger.info("Aggregation starting")
          r = retryable(AGGREGATION_JOB) do
            @client.search(aggregation_options(query_object))
          end
          @plugin.push_hit(r, output_queue, 'aggregations') if r
        end
      end
    end
  end
end
