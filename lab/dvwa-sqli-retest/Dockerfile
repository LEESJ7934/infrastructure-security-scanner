FROM ghcr.io/digininja/dvwa:068d974@sha256:1af2cedda7617e4d22937e61c98bbf71d8b74b98e46f5e41dd6aa0a5183311b0

COPY low.php /var/www/html/vulnerabilities/sqli/source/low.php
RUN php -l /var/www/html/vulnerabilities/sqli/source/low.php

COPY xss-reflected-low.php /var/www/html/vulnerabilities/xss_r/source/low.php
RUN php -l /var/www/html/vulnerabilities/xss_r/source/low.php

COPY file-upload-low.php /var/www/html/vulnerabilities/upload/source/low.php
RUN php -l /var/www/html/vulnerabilities/upload/source/low.php \
    && install -d -m 0700 -o www-data -g www-data /var/lib/dvwa-uploads
