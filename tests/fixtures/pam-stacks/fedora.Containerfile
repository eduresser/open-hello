FROM registry.fedoraproject.org/fedora:latest
RUN dnf -y install --setopt=install_weak_deps=False gcc pam-devel sudo cpio shadow-utils \
 && cd /tmp && dnf -y download sddm \
 && rpm2cpio sddm-*.rpm | (cd / && cpio -idm "./etc/pam.d/*") && rm sddm-*.rpm \
 && useradd -m hello && echo 'hello:Correct-Horse-7' | chpasswd && dnf clean all
