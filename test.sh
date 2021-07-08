#!/bin/bash
COMPOSE_FILE=dev/docker-compose.yml
#docker-compose -f ${COMPOSE_FILE} up -d
jest --forceExit
#docker-compose -f ${COMPOSE_FILE} down