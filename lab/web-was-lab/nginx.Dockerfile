FROM nginx:1.30.6-alpine
ARG LAB_STAGE=before
COPY before/nginx.conf /opt/lab/before.conf
COPY after/nginx.conf /opt/lab/after.conf
RUN test "$LAB_STAGE" = before -o "$LAB_STAGE" = after && cp /opt/lab/$LAB_STAGE.conf /etc/nginx/nginx.conf && mkdir -p /srv/files /srv/private && printf 'non-sensitive LAB fixture\n' > /srv/files/example.txt && printf 'LAB_PRIVATE_FIXTURE\n' > /srv/private/example.txt
RUN if [ "$LAB_STAGE" = before ]; then printf 'LAB_SAMPLE_BACKUP\n' > /srv/files/sample.bak; else rm -f /srv/private/example.txt && rm -rf /usr/share/nginx/html; fi
COPY start-nginx.sh /opt/lab/start.sh
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/opt/lab/start.sh"]
CMD ["nginx", "-g", "daemon off;"]
