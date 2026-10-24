FROM docker.io/library/archlinux:base
RUN pacman -Syu --noconfirm gcc sudo \
 && pacman -Sw --noconfirm sddm \
 && bsdtar -xf $(ls /var/cache/pacman/pkg/sddm-*.pkg.tar.zst | head -n 1) -C / etc/pam.d \
 && useradd -m hello && echo 'hello:Correct-Horse-7' | chpasswd && rm -rf /var/cache/pacman/pkg/*
