# inspect-certificate

[![License](https://img.shields.io/github/license/meysam81/inspect-certificate?style=flat-square)](https://github.com/meysam81/inspect-certificate/blob/main/LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/meysam81/inspect-certificate?style=flat-square)](https://github.com/meysam81/inspect-certificate/releases)
[![GitHub Stars](https://img.shields.io/github/stars/meysam81/inspect-certificate?style=flat-square&logo=github)](https://github.com/meysam81/inspect-certificate/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/meysam81/inspect-certificate?style=flat-square&logo=github)](https://github.com/meysam81/inspect-certificate/issues)
[![Go Report Card](https://goreportcard.com/badge/github.com/meysam81/inspect-certificate?style=flat-square)](https://goreportcard.com/report/github.com/meysam81/inspect-certificate)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg?style=flat-square&logo=go)](https://go.dev)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-meysam81%2Finspect--certificate-blue?style=flat-square&logo=docker)](https://hub.docker.com/r/meysam81/inspect-certificate)
[![Docker Pulls](https://img.shields.io/docker/pulls/meysam81/inspect-certificate?style=flat-square&logo=docker)](https://hub.docker.com/r/meysam81/inspect-certificate)
[![Docker Image Size (tag)](https://img.shields.io/docker/image-size/meysam81/inspect-certificate/v1)](https://hub.docker.com/r/meysam81/inspect-certificate)

Zero-dependency Go CLI for TLS certificate inspection.

## Install

```bash
go install github.com/meysam81/inspect-certificate@latest
```

Or download a pre-built binary from the [releases page](https://github.com/meysam81/inspect-certificate/releases).

## Usage

```bash
# Quick check with expiration status
$ inspect-certificate meysam.io
Subject:     meysam.io
Issuer:      C=US, O=Let's Encrypt, CN=R13
Valid From:  Dec 10 2025 19:16:11 UTC
Valid Until: Mar 10 2026 19:16:10 UTC
Status:      Valid (67 days left)
DNS Names:   meysam.io
Serial:      05:44:f6:d1:df:57:c9:1e:3b:98:e0:17:c4:5c:1e:0a:b9:2f

# Detailed OpenSSL-style output
$ inspect-certificate --format=openssl meysam.io
```

## Why?

Because `openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -text -noout` is too much to type.
