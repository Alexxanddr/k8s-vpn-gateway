FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w -buildid=' -o /gateway ./cmd/gateway
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache openvpn=2.7.7-r0 nftables=1.1.6-r1 iproute2=7.0.0-r0 ca-certificates=20261020-r0 libcrypto3=3.5.9-r0 libssl3=3.5.9-r0
COPY --from=build /gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
