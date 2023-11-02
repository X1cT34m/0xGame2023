while true
    do
        echo 'start docker compose'
        docker compose up -d
        sleep 5m
        echo 'stop docker compose'
        docker compose down
    done