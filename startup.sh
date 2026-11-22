#!/bin/bash
set -e

iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254 -j DROP

export DOCKER_CONFIG=/tmp/.docker
mkdir -p $DOCKER_CONFIG
/usr/bin/docker-credential-gcr configure-docker --registries=asia-northeast1-docker.pkg.dev

docker rm -f honeypot || true

docker run -d \
  --name honeypot \
  --restart unless-stopped \
  --read-only \
  --cap-drop=ALL \
  --user 65534:65534 \
  --memory=256m --cpus=0.5 \
  -p 80:8080 \
  --log-driver=gcplogs \
  asia-northeast1-docker.pkg.dev/honeypot-515503/cloud-run-source-deploy/honeypot-http@sha256:a886cad31be4612b23118072841f32e4d8e5885728f16d6c7f079b4f23c9ec12
