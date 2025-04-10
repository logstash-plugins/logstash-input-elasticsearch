require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class Esql
        include LogStash::Util::Loggable

        ESQL_JOB = "ES|QL job"

        # Initialize the ESQL query executor
        # @param client [Elasticsearch::Client] The Elasticsearch client instance
        # @param plugin [LogStash::Inputs::Elasticsearch] The parent plugin instance
        def initialize(client, plugin)
          @client = client
          @plugin_params = plugin.params
          @plugin = plugin
          @retries = @plugin_params["retries"]
          @query = @plugin_params["query"]
          unless @query.include?('METADATA')
            logger.warn("The query doesn't have METADATA keyword. Including it makes _id and _version available in the documents", {:query => @query})
          end
        end

        # Execute the ESQL query and process results
        # @param output_queue [Queue] The queue to push processed events to
        # @param query A query to be executed
        def do_run(output_queue, query)
          logger.info("ES|QL executor starting")
          response = retryable(ESQL_JOB) do
            @client.esql.query({ body: { query: query }, format: 'json' })
          end
          # retriable already printed error details
          return if response == false

          if response&.headers&.dig("warning")
            logger.warn("ES|QL executor received warning", {:message => response.headers["warning"]})
          end
          if response['values'] && response['columns']
            process_response(response['values'], response['columns'], output_queue)
          end
        end

        # Execute a retryable operation with proper error handling
        # @param job_name [String] Name of the job for logging purposes
        # @yield The block to execute
        # @return [Boolean] true if successful, false otherwise
        def retryable(job_name, &block)
          stud_try = ::LogStash::Helpers::LoggableTry.new(logger, job_name)
          stud_try.try((@retries + 1).times) { yield }
        rescue => e
          error_details = {:message => e.message, :cause => e.cause}
          error_details[:backtrace] = e.backtrace if logger.debug?
          logger.error("#{job_name} failed with ", error_details)
          false
        end

        private

        # Process the ESQL response and push events to the output queue
        # @param values [Array[Array]] The ESQL query response hits
        # @param columns [Array[Hash]] The ESQL query response columns
        # @param output_queue [Queue] The queue to push processed events to
        def process_response(values, columns, output_queue)
          values.each do |value|
            mapped_data = map_column_and_values(columns, value)
            @plugin.decorate_and_push_to_queue(output_queue, mapped_data)
          end
        end

        # Map column names to their corresponding values
        # @param columns [Array] Array of column definitions
        # @param values [Array] Array of values for the current row
        # @return [Hash] Mapped data with column names as keys
        def map_column_and_values(columns, values)
          columns.each_with_index.with_object({}) do |(column, index), mapped_data|
            mapped_data[column["name"]] = values[index]
          end
        end
      end
    end
  end
end