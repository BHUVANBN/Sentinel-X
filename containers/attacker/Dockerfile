FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    curl \
    netcat-openbsd \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY attack_orchestrator.sh /attack_orchestrator.sh
RUN chmod +x /attack_orchestrator.sh

CMD ["sleep", "infinity"]
