#!/bin/sh
docker-compose -f dev/postgres.yml -f dev/interossea-mounted.yml up -d