FROM alpine:3.22
RUN apk add --no-cache frr iproute2 nftables python3 tini
COPY start.py collect.py harden.py before.nft after.nft /opt/network-lab/
COPY frr.conf /etc/frr/frr.conf
RUN mkdir -p /opt/network-lab/demo /run/frr && \
    printf 'Isolated network LAB demo only\n' > /opt/network-lab/demo/index.html && \
    chown -R frr:frr /etc/frr /run/frr
ENTRYPOINT ["/sbin/tini", "--", "python3", "/opt/network-lab/start.py"]
