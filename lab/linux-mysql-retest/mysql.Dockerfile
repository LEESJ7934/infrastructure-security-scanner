FROM mysql:8.4.13
COPY start-mysql.sh harden-mysql.sh /opt/lab/
COPY init-mysql.sh /docker-entrypoint-initdb.d/10-lab.sh
RUN chmod 0644 /docker-entrypoint-initdb.d/10-lab.sh
ENTRYPOINT ["bash", "/opt/lab/start-mysql.sh"]
CMD ["mysqld", "--local-infile=ON", "--require-secure-transport=OFF"]
