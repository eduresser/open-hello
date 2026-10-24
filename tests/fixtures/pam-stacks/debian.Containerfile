FROM docker.io/library/debian:13
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev libpam0g-dev sudo \
 && cd /tmp && apt-get download sddm && dpkg-deb -x sddm_*.deb x && cp x/etc/pam.d/sddm* /etc/pam.d/ && rm -rf x sddm_*.deb \
 && useradd -m hello && echo 'hello:Correct-Horse-7' | chpasswd && rm -rf /var/lib/apt/lists/*
