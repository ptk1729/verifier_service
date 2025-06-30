FROM ubuntu:22.04


RUN apt update -y && apt install -y golang golint git

RUN apt-get update && apt-get install -y \
    wget \
    git \
    ca-certificates \
    build-essential \
    curl

RUN cd /tmp && \
    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest


COPY . /app

WORKDIR /app


ENTRYPOINT ["go", "run", "main.go"]
CMD []