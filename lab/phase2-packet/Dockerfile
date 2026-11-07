# Reuse the existing local LAB image; no extra packages or host installation.
FROM scanner-p2net:local
COPY start.py router.nft client.nft /opt/packet-lab/
ENTRYPOINT ["/sbin/tini", "--", "python3", "/opt/packet-lab/start.py"]
