#!/bin/sh
docker-compose -f dev/postgres.yml -f dev/interossea-build.yml up -d --build