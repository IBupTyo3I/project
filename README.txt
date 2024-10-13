Установка программ по серверам

На 1-й сервер вам нужно установить Zabbix-server, Grafana, Ansible, Filebeat, OpenVPN-server

На 2-й сервер вам нужно будет установить Nginx, Apache, PHP, Zabbix-agent, Bind, Mail, Filebeat. Pgadmin

На 3-й сервер — PostgreSQL-12, Zabbix-agent, ELК

Ну начнем:

На первом сервере 51.250.35.90 установим Zabbix-server. Воспользуемся мы официальным сайтом по установки Zabbix https://www.zabbix.com/ru

Запустим новый сеанс оболочки с привилегиями root.

$ sudo -s

Установим репозиторий Zabbix

# wget https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu20.04_all.deb
# dpkg -i zabbix-release_6.0-4+ubuntu20.04_all.deb
# apt update

Установим Zabbix сервер, веб-интерфейс и агент

# apt install zabbix-server-mysql zabbix-frontend-php zabbix-nginx-conf zabbix-sql-scripts zabbix-agent

Установим и запустим сервер базы данных.

# mysql -uroot -p
password
mysql> create database zabbix character set utf8mb4 collate utf8mb4_bin;
mysql> create user zabbix@localhost identified by ‘password’;
mysql> grant all privileges on zabbix.* to zabbix@localhost;
mysql> set global log_bin_trust_function_creators = 1;
mysql> quit;

На хосте Zabbix сервера импортируем начальную схему и данные.

# zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql —default-character-set=utf8mb4 -uzabbix -p zabbix

Выключаем опцию log_bin_trust_function_creators 
управляет тем, должно ли двоичное ведение журнала доверять создателям хранимых функций

# mysql -uroot -p
password
mysql> set global log_bin_trust_function_creators = 0;
mysql> quit;

Настроим базу данных для Zabbix сервера

Отредактируем файл /etc/zabbix/zabbix_server.con

DBPassword=password

Настроим PHP для веб-интерфейса

Отредактируемфайл /etc/zabbix/nginx.conf раскомментируйте и настройте директивы ‘listen’ и ‘server_name’.

# listen 8080;
# server_name example.com;

Запустим процессы Zabbix сервера и агента и настроем их запуск при загрузке ОС

# systemctl restart zabbix-server zabbix-agent nginx php7.4-fpm
# systemctl enable zabbix-server zabbix-agent nginx php7.4-fpm

Заходим на созданную нами Web страницу и вводим данные

http://51.250.35.90/index.php

А теперь давайте приступим к установке Grafana и необходимого плагина.

Для начала нам нужно добавить репозиторий, из которого будем производить установку (вводим следующие команды):

sudo apt-get install -y apt-transport-https
sudo apt-get install -y software-properties-common wget
wget -q -O — https://packages.grafana.com/gpg.key | sudo apt-key add —
echo «deb https://packages.grafana.com/enterprise/deb stable main» |
sudo tee -a /etc/apt/sources.list.d/grafana.list

Следующим шагом обновляем список пакетов:

sudo apt-get update

Устанавливаем Grafana:

sudo apt-get install grafana

После чего устанавливаем сервис grafana-server и добавляем его в автозагрузку, чтобы он запускался как служба при загрузке системы:

sudo systemctl start grafana-server

sudo systemctl enable grafana-server

Далее проверяем, запустился ли наш сервис и перейдем на сайт

sudo systemctl status grafana-server
http://51.250.35.90:3000/

Установлю Ansible и сразу создам роли и playbook

Для начала обновлю пакеты:

sudo apt update

Установлю software-properties-common, который упрощает работу со сторонними репозиториями:

sudo apt install software-properties-common

Добавьте репозиторий ppa/ansible:

sudo apt-add-repository ppa:ansible/ansible

И, наконец, установлю Ansible:

sudo apt install ansible

Настрою файл Hosts.

Укажу что и на каких серверах будут прокатываться роли

sudo nano /etc/ansible/hosts

[servers]

server2.my ansible_ssh_host=51.250.34.42

server3.my ansible_ssh_host=51.250.45.63
[apache]
server2.my ansible_ssh_host=51.250.34.42
[nginx]
server2.my ansible_ssh_host=51.250.34.42
[php]
server2.my ansible_ssh_host=51.250.34.42
[bind9]
server2.my ansible_ssh_host=51.250.34.42
Проверим:


Создадим папку playbook и напишем роли, с ними можете ознакомиться на моем Github https://github.com/IBupTyo3I/project

Следующим нашим шагом будет установка OpenVPN и связка сервера с клиентами

Конфиг сервера:


Server1-51.250.35.90
Конфиг клиента: web и zabbix


Server2- 51.250.34.42

Server3-51.250.45.63

Разумеется без чувствительной информации со стороны сертификатов

Процесс установки и настройки

apt update && apt upgrade -y

sudo apt install openvpn easy-rsa -y
sudo mkdir /etc/openvpn/easy-rsa
sudo cp -R /usr/share/easy-rsa /etc/openvpn/
cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa init-pki

cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa build-ca
Common Name (eg: your user, host, or server name) [Easy-RSA CA]:skillservervpn

cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa gen-dh
cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa build-server-full servervpn nopass

cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/issued/servervpn.crt /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/private/servervpn.key /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/

cp /etc/openvpn/dh.pem /etc/openvpn/easy-rsa/pki/
cp /etc/openvpn/servervpn.key /etc/openvpn/easy-rsa/pki/private/
cp /etc/openvpn/ca.crt /etc/openvpn/easy-rsa/pki/

systemctl restart openvpn@servervpn
systemctl enable openvpn@servervpn

echo net.ipv4.ip_forward=1 >> /etc/sysctl.confsysctl -p

sudo ufw allow 1194/udp
sudo ufw allow 1194/tcp

vim /etc/ufw/before.rules
# don’t delete the ‘COMMIT’ line or these rules won’t be processed
COMMIT
+# START OPENVPN RULES
+# NAT table rules
+*nat
+:POSTROUTING ACCEPT [0:0]
+# Allow traffic from OpenVPN client to eth0
+-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
+COMMIT
+# END OPENVPN RULES

sed -i ‘s/DROP/ACCEPT/’ /etc/default/ufw

sudo ufw enable

cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa build-client-full clientvpn nopass

sudo mkdir -p /etc/openvpn/clients/clientvpn

cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/clients/clientvpn/
cp /etc/openvpn/easy-rsa/pki/issued/clientvpn.crt /etc/openvpn/clients/clientvpn/
cp /etc/openvpn/easy-rsa/pki/private/clientvpn.key /etc/openvpn/clients/clientvpn/

cat /etc/openvpn/clients/clientvpn/ca.crt >> /etc/openvpn/clients/clientvpn.conf
echo \ >> /etc/openvpn/clients/clientvpn.conf
echo \ >> /etc/openvpn/clients/clientvpn.conf
cat /etc/openvpn/clients/clientvpn/clientvpn.crt >> /etc/openvpn/clients/clientvpn.conf
echo \<\/cert> >> /etc/openvpn/clients/clientvpn.conf
echo \ >> /etc/openvpn/clients/clientvpn.conf
cat /etc/openvpn/clients/clientvpn/clientvpn.key >> /etc/openvpn/clients/clientvpn.conf
echo \<\/key> >> /etc/openvpn/clients/clientvpn.conf

Настройки на стороне клиента

apt update && apt upgrade -y

sudo apt install openvpn -y

копируем настройки конфигов с сервера: Web и Zabbix

sudo openvpn /etc/openvpn/servervpn.conf
openvpn /etc/openvpn/web.conf &
openvpn /etc/openvpn/zabbix.conf &




Initialization Sequence Completed

DNS установлю дистрибутив кэширующий DNS

sudo apt install bind9
Запустим службу:

sudo systemctl start bind9

Включим её автозагрузку, чтобы она была доступна после перезагрузки:

sudo systemctl enable named
И произведем настройку в myzones


Поднимаю свой сайт с reverse proxy, почту, антиспам и антивирус на втором сервере 51.250.34.42

Устанавливаем MySQL

sudo apt install mysql-server mysql-client -yПодключаемся к MySQL, добавляем базу и пользователя для WordPress.

sudo mysql

mysql> CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;

mysql> CREATE USER ‘wordpressuser’@’localhost’ IDENTIFIED BY ‘password’;

mysql> GRANT ALL ON wordpress.* TO ‘wordpressuser’@’localhost’;

mysql> FLUSH PRIVILEGES;

Установка WordPress

Устанавливаем WordPress и необходимые для него пакеты.

sudo apt install wordpress apache2 php libapache2-mod-php php-mysql php-curl php-gd php-mbstring php-xml php-xmlrpc php-soap php-intl php-zip -y

Разрешаем rewrite модуль в apache.

sudo a2enmod rewrite

Перегружаем apache и проверяем, что модуль rewrite включен.

sudo systemctl restart apache2

apachectl -M | grep -i rewrite_module

Добавление сайта WordPress

Создаём сайт в apache.

sudo bash -c ‘cat > /etc/apache2/sites-available/wordpress.conf <<EOF

Alias /blog /usr/share/wordpress

<Directory /usr/share/wordpress>

Options FollowSymLinks

AllowOverride All

DirectoryIndex index.php

Order allow,deny

Allow from all

</Directory>

<Directory /usr/share/wordpress/wp-content>

Options FollowSymLinks

Order allow,deny

Allow from all

</Directory>

EOF’

Добавляем его в активную конфигурацию.

sudo ln -s /etc/apache2/sites-available/wordpress.conf /etc/apache2/sites-enabled/wordpress.conf

Добавляем конфигурацию для WordPress.

sudo cp /usr/share/wordpress/wp-config-sample.php /etc/wordpress/config-default.php

Подключение базу данных.

sudo sed -i ‘s/database_name_here/wordpress/’ /etc/wordpress/config-default.php

sudo sed -i ‘s/username_here/wordpressuser/’ /etc/wordpress/config-default.php

sudo sed -i ‘s/password_here/password/’ /etc/wordpress/config-default.php

sudo sed -i ‘s/define( .DB_COLLATE., .. );/define( \x27DB_COLLATE\x27, \x27utf8_unicode_ci\x27 );/’ /etc/wordpress/config-default.php


Перегружаю apache.

sudo systemctl restart apache2

Для корректной работы WordPress нужны права на редактирования его файлов.

sudo chown www-data:www-data -R /usr/share/wordpress

sudo find /usr/share/wordpress -type d -exec chmod 755 {} \;

sudo find /usr/share/wordpress -type f -exec chmod 644 {} \;

Меняем адрес сайта WordPress с ИП на хост.
Меняем /blog на нормальный хост http://www.51.250.34.42.nip.io.

Создаём резервную копию базы данных.

sudo mysqldump wordpress > wordpress.sql

cp wordpress.sql wordpress_org.sql

Если nginx вы установили на другом сервера, а него другой ИП адрес, то вы можете сразу поменять и ИП.

sed -i ‘s/http:..51.250.34.42.blog/http:\/\/www.51.250.34.42.nip.io/g’ wordpress.sql

Перезаливаем базу.

sudo mysql wordpress < wordpress.sql

Создаём сайт в apache

sudo bash -c ‘cat > /etc/apache2/sites-available/www.51.250.34.42.nip.io.conf <<EOF

<VirtualHost *:80>

ServerName www.51.250.34.42.nip.io

ServerAlias 51.250.34.42.nip.io mail.51.250.34.42.nip.io

ServerAdmin admin@localhost

DocumentRoot /usr/share/wordpress

ErrorLog \${APACHE_LOG_DIR}/www.51.250.34.42.nip.io_error.log

CustomLog \${APACHE_LOG_DIR}/www.51.250.34.42.nip.io_access.log combined

<Directory /usr/share/wordpress>

Options FollowSymLinks

AllowOverride All

DirectoryIndex index.php

Order allow,deny

Allow from all

</Directory>

<Directory /usr/share/wordpress/wp-content>

Options FollowSymLinks

Order allow,deny

Allow from all

</Directory>

</VirtualHost>

EOF’

Удаляем старый сайт

sudo unlink /etc/apache2/sites-enabled/wordpress.conf

Добавляем новый

sudo ln -s /etc/apache2/sites-available/www.51.250.34.42.nip.io.conf /etc/apache2/sites-enabled/www.51.250.34.42.nip.io.conf

Перегружаем apache

Sudo systemctl restart apache2

Можем посмотреть логи, если что-то пошло не так.

sudo bash -c «tail -f /var/log/apache2/www.51.250.34.42.nip.io_*»

Подключаем сертификат ssl

Разрешаем ssl модуль в apache.

sudo a2enmod ssl

Перегружаем apache.

sudo systemctl restart apache2

Для получения бесплатного ssl сертификата от Let’s Encrypt, установим репозиторий.

sudo add-apt-repository ppa:certbot/certbot

Установим пакет certbot

sudo apt install certbot python3-certbot-apache -y

Получим ssl сертификат на хосты www.51.250.34.42.nip.io, 51.250.34.42.nip.io и mail.51.250.34.42.nip.io

sudo certbot —apache -d www.51.250.34.42.nip.io -d 51.250.34.42.nip.io -d mail.51.250.34.42.nip.io

Enter email address (used for urgent renewal and security notices) (Enter ‘c’ to

cancel): my@email.com

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —

(A)gree/(C)ancel: A

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —

(Y)es/(N)o: N

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —

1: No redirect — Make no further changes to the webserver configuration.

2: Redirect — Make all requests redirect to secure HTTPS access.

Select the appropriate number [1-2] then [enter] (press ‘c’ to cancel): 1

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —

Congratulations! You have successfully enabled https://www.51.250.34.42.nip.io,

https://51.250.34.42.nip.io, and https://mail.51.250.34.42.nip.io

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —

Подготавливаем apache для работы с nginx
Так как мы будем использовать один сервер, то поменям порты в apache, что бы не было конфликтов с nginx.

Меняем порты для сайта на http.

sudo sed -i ‘s/:80/:8080/’ /etc/apache2/sites-available/www.51.250.34.42.nip.io.conf

Меняем порты для сайта на https.

sudo sed -i ‘s/:443/:8081/’ /etc/apache2/sites-available/www.51.250.34.42.nip.io-le-ssl.conf

Удаляем сайт по умолчанию.

sudo unlink /etc/apache2/sites-enabled/000-default.conf

Меняем порты в apache.

sudo sed -i ‘s/Listen 80/Listen 8080/’ /etc/apache2/ports.conf

sudo sed -i ‘s/Listen 443/Listen 8081/’ /etc/apache2/ports.conf

Перегружаем apache.

sudo systemctl restart apache2

Добавляем nginx как reverse proxy для WordPress
Устанавливаем nginx

sudo apt install nginx -y

Создаём новый сайт по умолчанию и перенаправляем весь трафик на apache.

sudo bash -c ‘cat > /etc/nginx/sites-enabled/default <<EOF

server {

listen 80 default_server;

server_name _;

location / {

proxy_pass http://127.0.0.1:8080;

proxy_set_header Host \$host;

proxy_set_header X-Real-IP \$remote_addr;

proxy_set_header X-Forwarded-Host \$host;

proxy_set_header X-Forwarded-Server \$host;

proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

proxy_set_header X-Forwarded-Proto \$scheme;

proxy_set_header X-Server-Address  \$server_addr;

 }

}

EOF’

Перегружаем nginx

sudo systemctl restart nginx

Добавляем https.

sudo bash -c ‘cat >> /etc/nginx/sites-enabled/default <<EOF

server {

 listen 443 ssl default_server;

 server_name _;

ssl_certificate /etc/letsencrypt/live/www.51.250.34.42.nip.io/fullchain.pem;

ssl_certificate_key /etc/letsencrypt/live/www.51.250.34.42.nip.io/privkey.pem;

location / {

proxy_pass https://127.0.0.1:8081;

proxy_set_header Host \$host;

proxy_set_header X-Real-IP \$remote_addr;

proxy_set_header X-Forwarded-Host \$host;

proxy_set_header X-Forwarded-Server \$host;

proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

 proxy_set_header X-Forwarded-Proto \$scheme;

proxy_set_header X-Server-Address  \$server_addr;

}

}

EOF’

Перегружаем nginx

sudo systemctl restart nginx

Проверяем сайт на https https://www.51.250.34.42.nip.io/ 

Можно теперь подключится и залогиниться как admin

https://www.51.250.34.42.nip.io/

Подключить нужные модули Backup и выбрать тему!

И сайт готов!

Приступаю к установки пака программ для хорошей работы EMAIL

Postfix
Запустим установку Postfix

sudo apt-get install postfix -y

Сначала выбираем Internet Site.

Потом вписываем наш хост с ИП, которое мы посмотрели ранее

51.250.34.42.nip.io

Настройка postfix
Поменяем локальные домены mydestination

sudo sed -i ‘s/^mydestination = .*/mydestination = localhost.$mydomain, localhost/’ /etc/postfix/main.cf

Добавим в конец настройки авторизации и доставку почты через dovecot.

sudo bash -c ‘cat >> /etc/postfix/main.cf <<EOF

smtpd_sasl_auth_enable = yes

smtpd_sasl_type = dovecot

smtpd_sasl_path = private/auth

virtual_transport = lmtp:unix:private/dovecot-lmtp

virtual_mailbox_domains = /etc/postfix/virtual_mailbox_domains

EOF’

Добавим наш домен 51.250.34.42.nip.io

sudo bash -c ‘echo «51.250.34.42.nip.io ok» > /etc/postfix/virtual_mailbox_domains’

sudo postmap /etc/postfix/virtual_mailbox_domains

Раскомментируем submission для приёма писем от почтовых клиентов.

sudo sed -i ‘s/^.submission/submission/’ /etc/postfix/master.cf

Dovecot
Установим dovecot.

sudo apt install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd

Создадим папку для приёма писем.

sudo mkdir -p /var/mail/vhosts/51.250.34.42.nip.io

Добавим пользователя vmail и дадим ему права на папки с почтой.

sudo groupadd -g 5000 vmail

sudo useradd -r -g vmail -u 5000 vmail -d /var/mail/vhosts -c «virtual mail user»

sudo chown -R vmail:vmail /var/mail/vhosts/

Поменяем авторизацию с системной на passwdfile.

sudo sed -i ‘/.*auth-system.conf.ext/d’ /etc/dovecot/conf.d/10-auth.conf

sudo sed -i ‘s/^..include auth-passwdfile.conf.ext/!include auth-passwdfile.conf.ext/’ /etc/dovecot/conf.d/10-auth.conf

Разрешим ssl подключения.

sudo sed -i ‘s/.*port = 993/    port = 993\n    ssl = yes/’ /etc/dovecot/conf.d/10-master.conf

sudo sed -i ‘s/.*port = 995/    port = 995\n    ssl = yes/’ /etc/dovecot/conf.d/10-master.conf

Меняем доставку почты lmtp на dovecot.

sudo sed -i ‘s/.*unix_listener lmtp.*/  unix_listener \/var\/spool\/postfix\/private\/dovecot-lmtp \{\n    mode = 0600\n    user = postfix\n    group = postfix/’ /etc/dovecot/conf.d/10-master.conf

Добавляем smtp авторизацию.

sudo sed -i ‘s/.*Postfix smtp-auth/  # Postfix smtp-auth\n  unix_listener \/var\/spool\/postfix\/private\/auth \{\n    mode = 0666\n    user = postfix\n    group = postfix\n }/’ /etc/dovecot/conf.d/10-master.conf

Меняем файл схему и формат авторизации.

sudo sed -i ‘s/.*args = scheme.*/  args = scheme=PLAIN username_format=%u \/etc\/dovecot\/dovecot-users/’ /etc/dovecot/conf.d/auth-passwdfile.conf.ext

sudo sed -i ‘N;s/userdb.*driver = passwd-file/userdb {\n    driver = static/’ /etc/dovecot/conf.d/auth-passwdfile.conf.ext

sudo sed -i ‘s/.*args = username_format.*/    args = uid=vmail gid=vmail home=\/var\/mail\/vhosts\/%d\/%n/’ /etc/dovecot/conf.d/auth-passwdfile.conf.ext

Добавляем почтовые ящики.

sudo bash -c ‘cat >> /etc/dovecot/dovecot-users<<EOF

admin@51.250.34.42.nip.io и пароль

info@51.250.34.42.nip.io и пароль

EOF’

Меняем формат почтового ящика на maildir.

sudo sed -i ‘s/^mail_location.*/mail_location = maildir:\/var\/mail\/vhosts\/%d\/%n/’ /etc/dovecot/conf.d/10-mail.conf

Перезапускаем сервисы.

sudo service postfix restart

sudo service dovecot restart

Проверяем подключение.

$ telnet localhost 110

Trying ::1…

Connected to localhost.

Escape character is ‘^]’.

+OK Dovecot (Ubuntu) ready.

user admin@51.250.34.42.nip.io

+OK

pass PASSWORD

+OK Logged in.

list

+OK 0 messages:

quit

+OK Logging out.

Connection closed by foreign host.

Roundcube
Устанавливаем Roundcube.

sudo apt install -y mysql-server roundcube

Настраиваем его для работы с базой данных: <Yes>

Добавляем Alias для подключения к почте в Apache.

sudo bash -c ‘echo «Alias /mail /usr/share/roundcube» > /etc/apache2/sites-available/030-roundcube.conf’

sudo ln -s /etc/apache2/sites-available/030-roundcube.conf /etc/apache2/sites-enabled/030-roundcube.conf

sudo systemctl restart apache2.service

ClamAV
Устанавливаем ClamAV.

sudo apt install clamav-daemon clamav clamsmtp -y

Меняем права на папках антивируса.

sudo chown -R clamsmtp:clamsmtp /var/spool/clamsmtp/

sudo chown -R clamsmtp:clamsmtp /var/run/clamsmtp/

Перегружаем clamsmtp

sudo systemctl restart clamsmtp

Добавляем сканирование антивирусом в postfix.

sudo bash -c ‘cat >>/etc/postfix/main.cf<<EOF

# Virusscanner

content_filter = scan:127.0.0.1:10026

receive_override_options = no_address_mappings

EOF’

sudo bash -c ‘cat >>/etc/postfix/master.cf<<EOF

# Antivirus

scan unix — — n — 16 smtp

-o smtp_send_xforward_command=yes

# For injecting mail back into postfix from the filter

127.0.0.1:10025 inet n — n — 16 smtpd

o content_filter=

-o receive_override_options=no_unknown_recipient_checks,no_header_body_checks

-o smtpd_helo_restrictions=

-o smtpd_client_restrictions=

-o smtpd_sender_restrictions=

-o smtpd_recipient_restrictions=permit_mynetworks,reject

-o mynetworks_style=host

-o smtpd_authorized_xforward_hosts=127.0.0.0/8

EOF’

sudo systemctl restart postfix

Настраиваем обновление базы вирусов.

sudo sed -i ‘s/^ScriptedUpdates yes/ScriptedUpdates no/’ /etc/clamav/freshclam.conf

sudo sed -i ‘/DatabaseMirror/d’ /etc/clamav/freshclam.conf

sudo bash -c ‘ echo «PrivateMirror https://tendence.ru/clamav» >>/etc/clamav/freshclam.conf’

Скачиваем базы.

sudo -u clamav wget -P /var/lib/clamav/ https://techplanet.pro/clamav/main.cvd

sudo -u clamav wget -P /var/lib/clamav/ https://techplanet.pro/clamav/daily.cvd

sudo -u clamav wget -P /var/lib/clamav/ https://techplanet.pro/clamav/bytecode.cvd

Перегружаем clamav.

sudo systemctl restart clamav-freshclam.service

sudo systemctl restart clamav-daemon

SpamAssassin
Устанавливаем SpamAssassin.

sudo apt install -y spamassassin spamc

Добавляем пользователя spamd.

sudo groupadd -g 5001 spamd

sudo useradd -u 5001 -g spamd -s /sbin/nologin -d /var/lib/spamassassin spamd

Создаём папку для SpamAssassin.

sudo mkdir /var/lib/spamassassin

sudo chown -R spamd:spamd /var/lib/spamassassin

Настраиваем SpamAssassin.

sudo sed -i ‘s/^OPTIONS=.*/OPTIONS=»—create-prefs —max-children 5 —username spamd —helper-home-dir \/var\/lib\/spamassassin\/ -s \/var\/lib\/spamassassin\/spamd.log»/’ /etc/default/spamassassin

sudo sed -i ‘s/^PIDFILE=.*/PIDFILE=»\/var\/lib\/spamassassin\/spamd.pid»/’ /etc/default/spamassassin

sudo sed -i ‘s/^CRON=.*/CRON=1/’ /etc/default/spamassassin

sudo sed -i ‘s/^. report_safe.*/report_safe 0/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. use_bayes.*/use_bayes 1/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. bayes_auto_learn.*/bayes_auto_learn 1/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. bayes_ignore_header/bayes_ignore_header/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. rewrite_header.*/rewrite_header Subject [***** SPAM _SCORE_ *****]/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. required_score.*/required_score 2.0/’ /etc/spamassassin/local.cf

sudo sed -i ‘s/^. required_score.*/required_score 2.0\nuse_bayes_rules 1\nskip_rbl_checks 0\nuse_razor2 0\nuse_dcc 0\nuse_pyzor 0/’ /etc/spamassassin/local.cf

Запускаем и ставим в автозагрузку.

sudo systemctl enable spamassassin.service

sudo systemctl restart spamassassin

Добавляем проверку на спам в postfix.

sudo sed -i ‘s/^\Wsmtp .*/ -o content_filter=spamassassin:dummy/’ /etc/postfix/master.cf

sudo bash -c ‘cat >> /etc/postfix/master.cf <<EOF

# SpamAssassin

spamassassin unix — n n — — pipe

flags=DROhu user=spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f \${sender} \${recipient}

EOF’

Обновляем правила SpamAssassin.

sudo sa-update

Перегружаем сервисы.

sudo systemctl restart spamassassin

sudo systemctl restart postfix

Проверяем работу спам фильтра обязательно с внешнего почтового сервера. Отправляем почту:

Кому: admin@51.250.34.42.nip.io

Тема: тест спама

Сообщение: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X


Всё в порядке. X-Spam-Flag: YES и X-Spam-Status: Yes, score=999.8

Устанавливаем Pgadmin и PostgreSQL

curl https://www.pgadmin.org/static/packages_pgadmin_org.pub | sudo apt-key add

sudo sh -c ‘echo «deb https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/$(lsb_release -cs) pgadmin4 main» > /etc/apt/sources.list.d/pgadmin4.list && apt update’

sudo apt install pgadmin4 -y
sudo /usr/pgadmin4/bin/setup-web.sh

На PostgreSQL вам создаю копию тестовой базы с именем dbname_fortests с очищенными таблицами (но сохранением структуры) boarding_passes, Bookings.

Выгружаем все в Pgadmin и сверяем, корректируем.


Pgadmin(boardingpasses)очищена таблицаСкачать

Pgadmin(bookings)очищена таблицаСкачать
Устанавливаем связку ELK и выводим мониторинг в Kibana

sudo apt update -y && sudo apt upgrade -y
sudo apt install net-tools -y
sudo ufw allow in 1278/udp

Настройка Syslog

sudo vi /etc/rsyslog.conf

открываем следующие строки, блок MODULES

module(load=»imudp»)
input(type=»imudp» port=»514″)

module(load=»imtcp»)
input(type=»imtcp» port=»514″)

sudo ufw allow in 514/udp

sudo systemctl daemon-reload
sudo systemctl enable rsyslog.service
sudo systemctl start rsyslog.service
sudo systemctl status rsyslog.service

sudo apt-get install apt-transport-https openjdk-11-jre-headless uuid-runtime pwgen

установка стека ELK (без Logstash): 7.17.9

sudo apt-key adv —keyserver hkp://keyserver.ubuntu.com:80 —recv B00A0BD1E2C63C11
echo «deb [arch=amd64] http://repo.mongodb.org/apt/ubuntu $(lsb_release -sc)/mongodb-org/5.0 multiverse» | sudo tee /etc/apt/sources.list.d/mongodb-org.list
sudo apt-get update
sudo apt-get install -y mongodb-org

добавим mongodb в автозагрузку и запустим его с дефолтными настройками:

sudo systemctl daemon-reload
sudo systemctl enable mongod.service
sudo systemctl start mongod.service
sudo systemctl status mongod.service

установка Elasticserch

Добавляем Зеркало Яндекс:
echo «deb [trusted=yes] https://mirror.yandex.ru/mirrors/elastic/7/ stable main» | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update -y
Выходит ошибка типа: GPG error: https://mirror.yandex.ru/mirrors/elastic/7 stable InRelease: The following signatures couldn’t be verified because the public key is not available: NO_PUBKEY D27D666CD88E42B4
Копируем ключ из ошибки. и выполняем следующие команды:
gpg —keyserver keyserver.ubuntu.com —recv D27D666CD88E42B4

gpg —export —armor D27D666CD88E42B4 | sudo apt-key add —
после этих манипуляций все ставится очень просто:
sudo apt install default-jdk
sudo apt install elasticsearch

sudo apt install filebeat

После этого весь стек elk устанавливается по команде apt install название программы

увеличиваем потребление оперативной памяти до 4Гб

создаём новый файл и вписываем туда две строчки:

sudo vi /etc/elasticsearch/jvm.options.d/xms
-Xms4g
-Xmx4g

редактируем конфигурационный файл:

sudo vi /etc/elasticsearch/elasticsearch.yml
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true

sudo ufw allow in 19532/tcp
sudo ufw allow in 80/tcp
sudo ufw allow in 5601/tcp
netstat -tulpn | grep 5601

добавим elasticsearch в автозагрузку и запустим его с дефолтными настройками:

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl restart elasticsearch.service
sudo systemctl status elasticsearch.service

проверка работы Elasticsearch

curl -k -X GET «http://localhost:9200/_cluster/health?pretty»

создаем пользователей

sudo -u root /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto

cохраняем вывод где-нибудь в home

sudo vi password

установка Kibana:

curl https://artifacts.elastic.co/downloads/kibana/kibana-8.14.3-linux-x86_64.tar.gz.sha512 | shasum -a 512 -c -tar -xzf kibana-8.14.3-linux-x86_64.tar.gz

Устанавливаем ключи:

wget -qO — https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add —

Устанавливаем https транспорт для apt.

sudo apt install apt-transport-https

sudo apt update
dpkg -i kibana-7.17.8-amd64.deb

теперь нам стоит изменить некоторые настройки kibana в файле конфигурации, предварительно создав его копию:

cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.bak

Откроем файл конфигурации:

sudo vi /etc/kibana/kibana.yml

server.port: 5601
server.host: 0.0.0.0
elasticsearch.username: «*******»
elasticsearch.password: zbYDXV*****ZhjMdA #сюда добавляем свой пароль
xpack.security.enabled: true

Добавьте Kibana в список приложений, запускаемых автоматически:

sudo systemctl enable kibana.service
sudo systemctl restart kibana.service
sudo systemctl status kibana.service

проверяем работу Kibana

Убедитесь, что Elasticsearh и Kibana использовали нашу сеть:

netstat -tulpn | grep 9200
netstat -tulpn | grep 5601

я захожу с пользователем
elastic + пароль, который сгенерировали ранее

Теперь настроим клиент

sudo apt update -y && sudo apt upgrade -y
sudo apt install net-tools -y
sudo ufw allow in 1278/udp

установка Linux, Nginx, MySQL, PHP (стека LEMP) в Ubuntu 20.04

sudo apt install nginx
sudo ufw app list
sudo ufw allow ‘Nginx HTTP’
sudo apt install mysql-server
sudo mysql
exit
sudo apt install php-fpm php-mysql
sudo mkdir /var/www/51.250.34.42.nip.io
sudo chown -R $USER:$USER /var/www/51.250.34.42.nip.io
sudo vi /etc/nginx/sites-available/51.250.34.42.nip.io
server {
listen 80;
server_name 51.250.34.42.nip.io;

root /var/www/51.250.34.42.nip.io;

index index.html index.htm index.php;

location / {
try_files $uri $uri/ =404;
}

location ~ \.php$ {
include snippets/fastcgi-php.conf;
fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;

}

location ~ /\.ht {
deny all;

}

}
sudo ln -s /etc/nginx/sites-available/51.250.34.42.nip.io /etc/nginx/sites-enabled/
sudo nginx -t
vi /var/www/51.250.34.42.nip.io/index.html
Добро пожаловать

<p> Добро пожаловать! Это наш сайт. </strong></p>

sudo nginx -t
http:/51.250.34.42.nip.io/

sudo systemctl reload nginx

vi /var/www/51.250.34.42.nip.io/info.php
<?php
phpinfo();

http://51.250.34.42.nip.io/info.php

sudo rm /var/www/51.250.34.42.nip.io/info.php

sudo systemctl reload nginx

sudo mysql

добавляем в mysql по очереди запросы

CREATE DATABASE example_database;
CREATE USER ‘example_user’@’%’ IDENTIFIED WITH mysql_native_password BY ‘password’;
GRANT ALL ON example_database.* TO ‘example_user’@’%’;
exit

mysql -u example_user -p

SHOW DATABASES;

CREATE TABLE example_database.todo_list (
item_id INT AUTO_INCREMENT,
content VARCHAR(255),
PRIMARY KEY(item_id)
);

INSERT INTO example_database.todo_list (content) VALUES («My first important item»);
SELECT * FROM example_database.todo_list;
exit

vi /var/www/51.250.34.42.nip.io/todo_list.php
<?php
$user = «example_user»;
$password = «password»;
$database = «example_database»;
$table = «todo_list»;

try {
$db = new PDO(«mysql:host=localhost;dbname=$database», $user, $password);
echo «

TODO

» . $row[‘content’] . «
«;
} catch (PDOException $e) {
print «Error!: » . $e->getMessage() . «
«;
die();
}

http://51.250.34.42.nip.io/todo_list.php

мы создали полноценный LEMP сервер, где БД и сайт взаимодействуют

теперь установим filebeat из директории home для передачи логов с Nginx и Mysql

#
server 51.250.45.63
client 51.250.34.42
sudo dpkg -i filebeat-7.17.8-amd64.deb
username: «*******»
password: «*******r»

добавляем параметры

sudo vi /etc/filebeat/filebeat.yml
output.elasticsearch:
hosts: [«51.250.45.63:9200»]
username: «admin»
password: «123»
setup.kibana:
host: «51.250.45.63»

Запускаем Filebeat с помощью следующих команд:

sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat

sudo filebeat modules enable system
sudo filebeat modules enable nginx
sudo filebeat modules enable mysql
sudo filebeat setup
sudo filebeat -e


ELKСкачать
Мониторинг работает!

Разворачиваем свой Zabbix-Server с Ansible и выводим мониторинг zabbix-agent на втором и третям сервере, а также мониторинг PostgreSQL и ELK


Zabbix-DashboardСкачать

Zabbix-HostsСкачать
Заходим на ранее установленный мной сайт Grafana

http://51.250.35.90:3000/


Мониторинг GrafanaСкачать
На dashboards видно что на всех трех серверах мониториться CPU, mem, disk usage. А также PostgreSQL и ELK

Заворачиваем это все в Docker-контейнер Zabbix, ELK, Grafana


Docker server1Скачать

Docker server3Скачать
И наш полноценный стак мониторинга готов!

В данном проекте я реализовал три виртуальные машины на базе ubuntu, c программами логирования и мониторинга серверов, а также собственной базой данных, почтой с антивирусом и антиспамом, внутреннею сеть VPN, и открытый интернету защищенный сайт.
