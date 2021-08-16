require 'elasticsearch'
require 'elasticsearch/transport/transport/connections/selector'

if Gem.loaded_specs['elasticsearch-transport'].version < Gem::Version.new("7.2.0")
  # elasticsearch-transport versions prior to 7.2.0 suffered of a race condition on accessing
  # the connection pool. This issue was fixed (in 7.2.0) with
  # https://github.com/elastic/elasticsearch-ruby/commit/15f9d78591a6e8823948494d94b15b0ca38819d1
  #
  # This plugin, at the moment, is using elasticsearch >= 5.0.5
  # When this requirement ceases, this patch could be removed.
  module Elasticsearch
    module Transport
      module Transport
        module Connections
          module Selector

            # "Round-robin" selector strategy (default).
            #
            class RoundRobin
              include Base

              # @option arguments [Connections::Collection] :connections Collection with connections.
              #
              def initialize(arguments = {})
                super
                @mutex = Mutex.new
                @current = nil
              end

              # Returns the next connection from the collection, rotating them in round-robin fashion.
              #
              # @return [Connections::Connection]
              #
              def select(options={})
                @mutex.synchronize do
                  conns = connections
                  if @current && (@current < conns.size-1)
                    @current += 1
                  else
                    @current = 0
                  end
                  conns[@current]
                end
              end
            end
          end
        end
      end
    end
  end
end