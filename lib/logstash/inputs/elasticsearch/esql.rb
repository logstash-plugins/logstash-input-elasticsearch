require 'logstash/helpers/loggable_try'

module LogStash
  module Inputs
    class Elasticsearch
      class Esql
        include LogStash::Util::Loggable

        ESQL_JOB = "ES|QL job"

        ESQL_PARSERS_BY_TYPE = Hash.new(lambda { |x| x }).merge(
          'date' => ->(value) { value && LogStash::Timestamp.new(value) },
          )

        # Initialize the ESQL query executor
        # @param client [Elasticsearch::Client] The Elasticsearch client instance
        # @param plugin [LogStash::Inputs::Elasticsearch] The parent plugin instance
        def initialize(client, plugin)
          @client = client
          @event_decorator = plugin.method(:decorate_event)
          @retries = plugin.params["retries"]

          target_field = plugin.params["target"]
          if target_field
            def self.apply_target(path) = "[#{target_field}][#{path}]"
          else
            def self.apply_target(path) = path
          end

          @query = plugin.params["query"]
          unless @query.include?('METADATA')
            logger.info("`METADATA` not found the query. `_id`, `_version` and `_index` will not be available in the result", {:query => @query})
          end
          logger.debug("ES|QL executor initialized with", {:query => @query})
        end

        # Execute the ESQL query and process results
        # @param output_queue [Queue] The queue to push processed events to
        # @param query A query (to obey interface definition)
        def do_run(output_queue, query)
          logger.info("ES|QL executor has started")
          response = retryable(ESQL_JOB) do
            @client.esql.query({ body: { query: @query }, format: 'json', drop_null_columns: true })
          end
          # retriable already printed error details
          return if response == false

          if response&.headers&.dig("warning")
            logger.warn("ES|QL executor received warning", {:warning_message => response.headers["warning"]})
          end
          columns = response['columns']&.freeze
          values = response['values']&.freeze
          logger.debug("ES|QL query response size: #{values&.size}")

          process_response(columns, values, output_queue) if columns && values
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
        # @param columns [Array[Hash]] The ESQL query response columns
        # @param values [Array[Array]] The ESQL query response hits
        # @param output_queue [Queue] The queue to push processed events to
        def process_response(columns, values, output_queue)
          column_specs = columns.map { |column| ColumnSpec.new(column) }
          values.each do |row|
            event = column_specs.zip(row).each_with_object(LogStash::Event.new) do |(column, value), event|
              # `unless value.nil?` is a part of `drop_null_columns` that if some of columns' values are not `nil`, `nil` values appear
              # we should continuously filter out them to achieve full `drop_null_columns` on each individual row (ideal `LIMIT 1` result)
              unless value.nil?
                field_reference = apply_target(column.field_reference)
                event.set(field_reference, ESQL_PARSERS_BY_TYPE[column.type].call(value))
              end
            end
            @event_decorator.call(event)
            output_queue << event
          rescue => e
            # if event creation fails with whatever reason, inform user and tag with failure and return entry as it is
            logger.warn("Event creation error, ", message: e.message, exception: e.class, data: { "columns" => columns, "values" => [row] })
            failed_event = LogStash::Event.new("columns" => columns, "values" => [row], "tags" => ['_elasticsearch_input_failure'])
            output_queue << failed_event
          end
        end
      end

      # Class representing a column specification in the ESQL response['columns']
      # The class's main purpose is to provide a structure for the event key
      # columns is an array with `name` and `type` pair (example: `{"name"=>"@timestamp", "type"=>"date"}`)
      # @attr_reader :name [String] The name of the column
      # @attr_reader :type [String] The type of the column
      class ColumnSpec
        attr_reader :name, :type

        def initialize(spec)
          @name = isolate(spec.fetch('name'))
          @type = isolate(spec.fetch('type'))
        end

        def field_reference
          @_field_reference ||= '[' + name.gsub('.', '][') + ']'
        end

        private
        def isolate(value)
          value.frozen? ? value : value.clone.freeze
        end
      end
    end
  end
end