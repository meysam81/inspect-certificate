# syntax=docker/dockerfile:1
FROM golang:1.25 AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG BUILT_BY=docker

WORKDIR /app

ENV CGO_ENABLED=0

COPY . .
COPY --from=frontend-builder /build/frontend/dist ./internal/api/dist

RUN --mount=type=cache,target=/go/pkg/mod \
    go build -ldflags="-s -w -extldflags '-static' -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} -X main.builtBy=${BUILT_BY}" -trimpath -o parse-dmarc .

FROM scratch AS final

VOLUME /data
ENV PARSE_DMARC_CONFIG=/app/config.json \
    DATABASE_PATH=/data/parse-dmarc.db

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/parse-dmarc /app/parse-dmarc

EXPOSE 8080

ENTRYPOINT ["/app/parse-dmarc"]
CMD ["--config=/app/config.json"]
