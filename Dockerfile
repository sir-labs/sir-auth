FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /sir-auth .

FROM alpine:3.22
RUN adduser -D -H app
COPY --from=build /sir-auth /usr/local/bin/sir-auth
USER app
EXPOSE 8080
ENTRYPOINT ["sir-auth"]
