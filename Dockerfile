FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod ./
COPY go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kgamesproxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kgamesproxy /kgamesproxy
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/kgamesproxy"]
