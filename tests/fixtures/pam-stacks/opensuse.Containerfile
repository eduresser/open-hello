FROM registry.opensuse.org/opensuse/tumbleweed
RUN zypper -n in --no-recommends gcc pam-devel sudo pam-config shadow cpio \
 && cd /tmp && zypper -n download sddm-qt6 \
 && rpm2cpio $(ls /var/cache/zypp/packages/*/*/sddm-qt6-*.rpm | head -n 1) | (cd / && cpio -idm "./usr/lib/pam.d/*") \
 && useradd -m hello && echo 'hello:Correct-Horse-7' | chpasswd && zypper -n clean -a
