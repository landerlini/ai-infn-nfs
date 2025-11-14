FROM python:alpine
LABEL maintainer = "Lucio Anderlini <Lucio.Anderlini@fi.infn.it>"
LABEL source = "https://github.com/anderlinil/ai-infn-nfs"
COPY README.md /

RUN apk add --no-cache --update --verbose nfs-utils bash iproute2 && \
    rm -rf /var/cache/apk /tmp /sbin/halt /sbin/poweroff /sbin/reboot && \
    mkdir -p /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery && \
    echo "rpc_pipefs    /var/lib/nfs/rpc_pipefs rpc_pipefs      defaults        0       0" >> /etc/fstab && \
    echo "nfsd  /proc/fs/nfsd   nfsd    defaults        0       0" >> /etc/fstab

RUN pip install fastapi uvicorn

COPY ai-infn-nfsd.sh /usr/bin/ai-infn-nfsd.sh
COPY apiserver.py /opt/ai-infn-nfs/apiserver.py

RUN chmod +x /usr/bin/ai-infn-nfsd.sh

ENTRYPOINT ["/usr/bin/ai-infn-nfsd.sh"]