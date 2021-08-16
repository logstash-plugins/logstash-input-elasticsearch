# encoding: utf-8
require "elasticsearch"
require "elasticsearch/transport/transport/http/manticore"

es_client_version = Gem.loaded_specs['elasticsearch-transport'].version
if es_client_version >= Gem::Version.new('7.2') && es_client_version < Gem::Version.new('7.16')
  # elasticsearch-transport 7.2.0 - 7.14.0 had a bug where setting http headers
  #   ES::Client.new ..., transport_options: { headers: { 'Authorization' => ... } }
  # would be lost https://github.com/elastic/elasticsearch-ruby/issues/1428
  #
  # NOTE: needs to be idempotent as filter ES plugin might apply the same patch!
  #
  # @private
  module Elasticsearch
    module Transport
      module Transport
        module HTTP
          class Manticore

            def apply_headers(request_options, options)
              headers = (options && options[:headers]) || {}
              headers[CONTENT_TYPE_STR] = find_value(headers, CONTENT_TYPE_REGEX) || DEFAULT_CONTENT_TYPE
              headers[USER_AGENT_STR] = find_value(headers, USER_AGENT_REGEX) || user_agent_header
              headers[ACCEPT_ENCODING] = GZIP if use_compression?
              (request_options[:headers] ||= {}).merge!(headers) # this line was changed
            end

          end
        end
      end
    end
  end
end