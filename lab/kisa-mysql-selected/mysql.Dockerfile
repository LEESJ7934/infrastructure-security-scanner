FROM mysql:8.4.13
COPY phase2-linux-mysql/start-mysql.sh phase2-linux-mysql/harden-mysql.sh /opt/lab/
COPY phase2-linux-mysql/init-mysql.sh /docker-entrypoint-initdb.d/10-lab.sh
COPY kisa-mysql-selected/init-selected.sh /docker-entrypoint-initdb.d/20-selected.sh
COPY kisa-mysql-selected/harden-selected.sh /opt/lab/harden-selected.sh
RUN chmod 0644 /docker-entrypoint-initdb.d/10-lab.sh /docker-entrypoint-initdb.d/20-selected.sh
ENTRYPOINT ["bash", "/opt/lab/start-mysql.sh"]
CMD ["mysqld", "--skip-name-resolve", "--innodb-buffer-pool-size=64M", "--innodb-redo-log-capacity=16M"]
