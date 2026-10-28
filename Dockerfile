# Build
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hakscan ./cmd/hakscan

# Runtime
FROM alpine:3.20
RUN adduser -D -g '' hakscan
COPY --from=build /hakscan /usr/local/bin/hakscan
USER hakscan
ENTRYPOINT ["hakscan"]
