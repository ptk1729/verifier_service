FROM golang:1.24.4-bookworm


WORKDIR /app

COPY . .
# COPY go.mod go.sum ./
# RUN go mod download

RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest

RUN go mod tidy
# RUN go build -o app

ENTRYPOINT ["go", "run", "main.go"]
CMD []