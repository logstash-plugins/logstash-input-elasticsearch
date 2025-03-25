require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class Esql
        include LogStash::Util::Loggable

        ESQL_JOB = "ES|QL job"

        def initialize(client, plugin)
          @client = client
          @plugin_params = plugin.params
          @plugin = plugin
          @retries = @plugin_params["retries"]

          @query = @plugin_params["query"]
          esql_options = @plugin_params["esql"] ? @plugin_params["esql"]: {}
          @esql_params = esql_options["params"] ? esql_options["params"] : {}
          # TODO: add filter as well
          # @esql_params = esql_options["filter"] | []
        end

        def retryable(job_name, &block)
          stud_try = ::LogStash::Helpers::LoggableTry.new(logger, job_name)
          stud_try.try((@retries + 1).times) { yield }
        rescue => e
          error_details = {:message => e.message, :cause => e.cause}
          error_details[:backtrace] = e.backtrace if logger.debug?
          logger.error("#{job_name} failed with ", error_details)
          false
        end

        def do_run(output_queue)
          logger.info("ES|QL executor starting")
          response = retryable(ESQL_JOB) do
            @client.esql.query({ body: { query: @query }, format: 'json' })
            # TODO: make sure to add params, filters, etc...
            # @client.esql.query({ body: { query: @query }, format: 'json' }.merge(@esql_params))

          end
          puts "Response: #{response.inspect}"
          if response && response['values']
            response['values'].each do |value|
              mapped_data = map_column_and_values(response['columns'], value)
              puts "Mapped Data: #{mapped_data}"
              @plugin.decorate_and_push_to_queue(output_queue, mapped_data)
            end
          end
        end

        def map_column_and_values(columns, values)
          puts "columns class: #{columns.class}"
          puts "values class: #{values.class}"
          puts "columns: #{columns.inspect}"
          puts "values: #{values.inspect}"
          mapped_data = {}
          columns.each_with_index do |column, index|
            mapped_data[column["name"]] = values[index]
          end
          puts "values: #{mapped_data.inspect}"
          mapped_data
        end
      end
    end
  end
end