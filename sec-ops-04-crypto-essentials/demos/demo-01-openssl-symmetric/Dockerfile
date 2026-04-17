FROM ubuntu:22.04

RUN apt-get update -q && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        openssl \
        xxd \
        python3 \
        file \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /demo
COPY demo.sh /demo/demo.sh
RUN chmod +x /demo/demo.sh

CMD ["/bin/bash", "/demo/demo.sh"]
