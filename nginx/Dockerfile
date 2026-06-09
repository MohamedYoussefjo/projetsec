FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    nginx \
    iptables \
    curl \
    ca-certificates \
    && rm -f /etc/nginx/sites-enabled/default \
    && rm -f /etc/nginx/sites-available/default \
    && rm -rf /var/lib/apt/lists/*

# Nginx config
COPY default.conf /etc/nginx/conf.d/default.conf

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
