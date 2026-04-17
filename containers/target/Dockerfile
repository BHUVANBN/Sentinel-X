FROM ubuntu:22.04

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    curl \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Create vulnerable user with weak credentials
RUN useradd -m -s /bin/bash admin && \
    echo "admin:admin" | chpasswd && \
    mkdir /var/run/sshd

# Configure SSH to allow password authentication and log to auth.log
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config

# Exposure
EXPOSE 22 80

# Start rsyslog, ssh, and apache manually in the foreground
CMD service rsyslog start && service ssh start && apache2ctl -D FOREGROUND
