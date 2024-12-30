FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN go build -o /dynamoc-dns-server ./cmd/dynamic-dns-server/main.go
CMD [ "/dynamic-dns-server" ]