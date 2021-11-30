#!/bin/bash

env

set -ex

export PATH=$BUILD_DIR/gradle/bin:$PATH

wait_for_es() {
  echo "Waiting for elasticsearch to respond..."
  es_url="http://elasticsearch:9200"
  if [[ "$SECURE_INTEGRATION" == "true" ]]; then
    es_url="https://elasticsearch:9200 -k"
  fi
  count=120
  while ! curl --tlsv1.3 -vik $es_url && [[ $count -ne 0 ]]; do
    count=$(( $count - 1 ))
    [[ $count -eq 0 ]] && return 1
    sleep 1
  done
  echo "Elasticsearch is Up !"

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
  wait_for_es
  bundle exec rspec -fd $extra_tag_args --tag es_version:$ELASTIC_STACK_VERSION spec/inputs/integration
fi
