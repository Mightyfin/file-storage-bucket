# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
 CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/document-api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/document-migrate ./cmd/migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/document-scanner ./cmd/scanner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/document-api /document-api
COPY --from=build /out/document-migrate /document-migrate
COPY --from=build /out/document-scanner /document-scanner
USER nonroot:nonroot
ENTRYPOINT ["/document-api"]
