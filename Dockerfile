FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w -buildid=' -o /gateway ./cmd/gateway
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache openvpn=2.7.7-r0 nftables=1.1.6-r1 iproute2=7.0.0-r0 ca-certificates=20261020-r0 libcrypto3=3.5.9-r0 libssl3=3.5.9-r0
COPY --from=build /gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
