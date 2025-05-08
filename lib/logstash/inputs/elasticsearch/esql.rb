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
            def self.apply_target(path); "[#{target_field}][#{path}]"; end
          else
            def self.apply_target(path); path; end
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
          sub_element_mark_map = mark_sub_elements(column_specs)
          multi_fields = sub_element_mark_map.filter_map { |key, val| key.name if val == true }
          logger.warn("Multi-fields found in ES|QL result and they will not be available in the event. Please use `RENAME` command if you want to include them.", { :detected_multi_fields => multi_fields }) if multi_fields.any?

          values.each do |row|
            event = column_specs.zip(row).each_with_object(LogStash::Event.new) do |(column, value), event|
              # `unless value.nil?` is a part of `drop_null_columns` that if some of columns' values are not `nil`, `nil` values appear
              # we should continuously filter out them to achieve full `drop_null_columns` on each individual row (ideal `LIMIT 1` result)
              # we also exclude sub-elements of main field
              if value && sub_element_mark_map[column] == false
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

        # Determines whether each column in a collection is a nested sub-element (example "user.age")
        # of another column in the same collection (example "user").
        #
        # @param columns [Array<ColumnSpec>] An array of objects with a `name` attribute representing field paths.
        # @return [Hash<ColumnSpec, Boolean>] A hash mapping each column to `true` if it is a sub-element of another field, `false` otherwise.
        # Time complexity: (O(NlogN+N*K)) where K is the number of conflict depth
        #   without (`prefix_set`) memoization, it would be O(N^2)
        def mark_sub_elements(columns)
          # Sort columns by name length (ascending)
          sorted_columns = columns.sort_by { |c| c.name.length }
          prefix_set = Set.new # memoization set

          sorted_columns.each_with_object({}) do |column, memo|
            # Split the column name into parts (e.g., "user.profile.age" → ["user", "profile", "age"])
            parts = column.name.split('.')

            # Generate all possible parent prefixes (e.g., "user", "user.profile")
            # and check if any parent prefix exists in the set
            parent_prefixes = (0...parts.size - 1).map { |i| parts[0..i].join('.') }
            memo[column] = parent_prefixes.any? { |prefix| prefix_set.include?(prefix) }
            prefix_set.add(column.name)
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