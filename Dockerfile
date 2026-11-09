FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/jitd ./cmd/jitd

FROM alpine:3.21

RUN mkdir -p /var/data
COPY --from=build /out/jitd /usr/local/bin/jitd

ENV PORT=8080
ENV JIT_CA_KEY_PATH=/var/data/ca_key
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/jitd"]
