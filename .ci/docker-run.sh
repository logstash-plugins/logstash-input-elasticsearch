#!/bin/bash

# This is intended to be run inside the docker container as the command of the docker-compose.
set -ex

cd .ci

if docker compose version >/dev/null 2>&1; then
    docker_compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    docker_compose=(docker-compose)
else
    echo "Neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 127
fi

if [ "$INTEGRATION" == "true" ]; then
    "${docker_compose[@]}" up --exit-code-from logstash
else
    "${docker_compose[@]}" up --exit-code-from logstash logstash
fi
