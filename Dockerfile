FROM golang:1.24-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -o /dynamic-dns-server ./cmd/dynamic-dns-server

FROM alpine:3

# The weekly rebuild relies on this to pick up fixes newer than the base image.
RUN apk upgrade --no-cache

COPY --from=build /dynamic-dns-server /dynamic-dns-server
CMD [ "/dynamic-dns-server" ]
