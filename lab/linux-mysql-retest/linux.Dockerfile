FROM ubuntu:noble-20261024.1
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server python3 rsyslog && rm -rf /var/lib/apt/lists/* && rm -f /etc/ssh/ssh_host_*key*
COPY before /opt/lab/before
COPY after /opt/lab/after
COPY start-linux.py collect-linux.py /opt/lab/
ARG LAB_STAGE=before
RUN test "$LAB_STAGE" = before -o "$LAB_STAGE" = after && printf '%s' "$LAB_STAGE" > /opt/lab/stage
ENTRYPOINT ["python3", "/opt/lab/start-linux.py"]
