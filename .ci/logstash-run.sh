#!/bin/bash

env

set -ex

export PATH=$BUILD_DIR/gradle/bin:$PATH

# CentOS 7 using curl defaults does not enable TLSv1.3
CURL_OPTS="-k --tlsv1.2 --tls-max 1.3"

wait_for_es() {
  es_url="http://elasticsearch:9200"
  if [[ "$SECURE_INTEGRATION" == "true" ]]; then
    es_url="https://elasticsearch:9200"
  fi
  count=120
  while ! curl $CURL_OPTS $es_url && [[ $count -ne 0 ]]; do
    count=$(( $count - 1 ))
    [[ $count -eq 0 ]] && return 1
    sleep 1
  done
  echo $(curl $CURL_OPTS -v $ES_URL)

  return 0
}

if [[ "$INTEGRATION" != "true" ]]; then
  bundle exec rspec -fd spec/inputs -t ~integration -t ~secure_integration
else
  if [[ "$SECURE_INTEGRATION" == "true" ]]; then
    extra_tag_args="--tag secure_integration"
  else
    extra_tag_args="--tag ~secure_integration --tag integration"
  fi

  echo "Waiting for elasticsearch to respond..."
  wait_for_es
  echo "Elasticsearch is Up !"
  bundle exec rspec -fd $extra_tag_args --tag es_version:$ELASTIC_STACK_VERSION spec/inputs/integration
fi
