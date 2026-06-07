FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    libpam-google-authenticator \
    libpam-modules \
    rsyslog \
    iptables \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Users
RUN useradd -m -s /bin/bash admin && \
    useradd -m -s /bin/bash testuser && \
    echo "testuser:password123" | chpasswd && \
    echo "admin:admin" | chpasswd

# SSH keys
RUN mkdir -p /home/admin/.ssh
COPY authorized_keys /home/admin/.ssh/authorized_keys
COPY google_authenticator /home/admin/.google_authenticator
RUN chown -R admin:admin /home/admin/.ssh /home/admin/.google_authenticator && \
    chmod 700 /home/admin/.ssh && \
    chmod 600 /home/admin/.ssh/authorized_keys && \
    chmod 400 /home/admin/.google_authenticator

# Configs
COPY sshd_config /etc/ssh/sshd_config
COPY sshd_pam    /etc/pam.d/sshd

# Faillock state directory
RUN mkdir -p /var/run/faillock && chmod 700 /var/run/faillock

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh


RUN mkdir -p /var/run/sshd

EXPOSE 2222
CMD ["/entrypoint.sh"]
