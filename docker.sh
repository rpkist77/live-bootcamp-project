#!/bin/bash
set -e

# Define the location of the .env file (change if needed)
ENV_FILE="./auth-service/.env"

# Check if the .env file exists
if ! [[ -f "$ENV_FILE" ]]; then
  echo "Error: .env file not found!"
  exit 1
fi

# Run docker compose commands using the env file directly
docker compose --env-file "$ENV_FILE" build
docker compose --env-file "$ENV_FILE" up