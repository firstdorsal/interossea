#!/bin/bash
COMPOSE_FILE=dev/db.yml
docker-compose -f ${COMPOSE_FILE} up -d
sleep 5
jest --forceExit
docker-compose -f ${COMPOSE_FILE} down