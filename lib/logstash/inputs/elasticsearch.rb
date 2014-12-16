# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/inputs/version"
require "base64"

# Read from an Elasticsearch cluster, based on search query results.
# This is useful for replaying test logs, reindexing, etc.
#
# Example:
# [source,ruby]
#     input {
#       # Read all documents from Elasticsearch matching the given query
#       elasticsearch {
#         host => "localhost"
#         query => '{ "query": { "match": { "statuscode": 200 } } }'
#       }
#     }
#
# This would create an Elasticsearch query with the following format:
# [source,json]
#     http://localhost:9200/logstash-*/_search?q='{ "query": { "match": { "statuscode": 200 } } }'&scroll=1m&size=1000
#
# TODO(sissel): Option to keep the index, type, and doc id so we can do reindexing?
class LogStash::Inputs::Elasticsearch < LogStash::Inputs::Base
  config_name "elasticsearch"

  default :codec, "json"

  # List of elasticsearch hosts to use for querying.
  config :hosts, :validate => :array

  # The HTTP port of your Elasticsearch server's REST interface.
  config :port, :validate => :number, :default => 9200

  # The index or alias to search.
  config :index, :validate => :string, :default => "logstash-*"

  # The query to be executed.
  config :query, :validate => :string, :default => "*"

  # Enable the Elasticsearch "scan" search type.  This will disable
  # sorting but increase speed and performance.
  config :scan, :validate => :boolean, :default => true

  # This allows you to set the maximum number of hits returned per scroll.
  config :size, :validate => :number, :default => 1000

  # This parameter controls the keepalive time in seconds of the scrolling
  # request and initiates the scrolling process. The timeout applies per
  # round trip (i.e. between the previous scan scroll request, to the next).
  config :scroll, :validate => :string, :default => "1m"

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # SSL
  config :ssl, :validate => :boolean, :default => false

  # SSL Certificate Authority file
  config :ca_file, :validate => :path

  public
  def register
    require "elasticsearch"

    @options = {
      index: @index,
      body: @query,
      scroll: @scroll,
      size: @size
    }

    @options[:search_type] = 'scan' if @scan

    transport_options = {}

    if @user && @password
      token = Base64.strict_encode64("#{@user}:#{@password.value}")
      transport_options[:headers] = { Authorization: "Basic #{token}" }
    end

    hosts = if @ssl then
      @hosts.map {|h| { host: h, scheme: 'https' } }
    else
      @hosts
    end

    if @ssl && @ca_file
      transport_options[:ssl] = { ca_file: @ca_file }
    end

    @client = Elasticsearch::Client.new hosts: hosts, transport_options: transport_options

  end # def register

  public
  def run(output_queue)

    # get first wave of data
    r = @client.search @options

    # since 'scan' doesn't return data on the search call, do an extra scroll
    if @scan
      r = scroll_request(r['_scroll_id'])
    end

    while r['hits']['hits'].any? do
      r['hits']['hits'].each do |event|
        decorate(event)
        output_queue << event
      end
      r = scroll_request(r['_scroll_id'])
    end
  end # def run

  private
  def scroll_request scroll_id
    @client.scroll(body: scroll_id, scroll: @scroll)
  end
end # class LogStash::Inputs::Elasticsearch
