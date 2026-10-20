FROM python:3.12.7-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir pyftpdlib==2.0.1
WORKDIR /lab
COPY lab/server.py /lab/server.py
COPY lab/start-ssh.sh /lab/start-ssh.sh
RUN chmod 0755 /lab/start-ssh.sh && mkdir -p /run/sshd /lab/ftp
EXPOSE 2121 2222 8080
CMD ["python","/lab/server.py"]
