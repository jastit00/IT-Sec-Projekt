# Server Setup

## Prerequisites

1. Server with a Linux distribution.
2. Domain(s) pointing to your server IP (e.g. example.com, auth.example.com, api.example.com).
3. Docker installed on your server.
4. Docker Compose installed on your server.
5. Dockerfiles in your project repository (for Frontend and Backend)
6. CICD Pipeline
7. Following directory structure:

project-root/ (e.g /opt/docker/)
│
├── docker-main/
│   ├── docker-compose.yaml
│   └── .env
│
├── docker-keycloak/
│   ├── docker-compose.yaml
│   └── .env
│
└── docker-traefik/
    ├── docker-compose.yaml
    ├── .env
    └── config/
        ├── dynamic.yaml
        └── traefik.yaml



## Installation and Working Steps

1. Prepare environment files (.env) with the content needed (example given). Exchange the <yourDomain> Tags with your Domain.

2. Prepare the Docker Compose files (docker-compose.yaml) with the content needed (example given). Exchange the <yourDomain> Tags with your Domain.

3. Create a bash script (e.g. deploy.sh) with the following content in the directory of your choice.
    ```sh
    #!/bin/bash

    PULL=false

    # Check for --pull option
    if [ "$1" == "--pull" ]; then
        PULL=true
        shift
    fi

    # List of directories
    DIRECTORIES=(
        "/opt/docker/docker-main"
        "/opt/docker/docker-keycloak"
        "/opt/docker/docker-traefik/"
    )

    # Loop through all directories
    for dir in "${DIRECTORIES[@]}"; do
        (
            cd "$dir" && \
            $PULL && docker compose pull
            docker compose up -d
        )
    done
    ```



## Setup Keycloak

1. Access Keycloak in your browser at `https://auth.<yourDomain>` and log in with the username `admin` and password `password`.

2. Create a new realm and create a new client with the following settings:
   #### Access Settings
    - Root URL: `https://<yourDomain>`
    - Home URL: `https://<yourDomain>`
    - Valid Redirect URIs: `https://<yourDomain>/*`
    - Valid Post Logout Redirect URIs: `https://<yourDomain>/*`
    - Web Origins: `*`
    - Admin URL: `https://<yourDomain>`
   #### Capability config
    - Authentication flow (Standard Flow and Direct Access Grants)

3. Create new user(s).
4. Create new role(s).
5. Assign role(s) to user(s).



## Setup Traefik

1. Change the email address in `traefik.yaml`.
2. Run the following command:
   ```sh
   touch acme.json && chmod 600 acme.json
   ```
3. Exchange the <yourDomain> Tags with your Domain.
4. Run the following command to create a Docker network:
   ```sh
   docker network create traefik
   ```



## Start Containers & Use the Application (Access Frontend)

1. In the directory where the deploy.sh file is located, start all containers (with the first command) or pull and then start all containers (with the secound command).
   ```sh
   ./deploy.sh
   ```
   ```sh
   ./deploy.sh --pull
   ```

2. Access your application at `https://<yourDomain>`.

