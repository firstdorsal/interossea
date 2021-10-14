#!/bin/bash
COMPOSE_FILE=dev/pg/db.yml
docker-compose -f ${COMPOSE_FILE} up -d
sleep 1
node --experimental-vm-modules node_modules/.bin/jest --forceExit --setupFiles dotenv/config --runInBand
docker-compose -f ${COMPOSE_FILE} down