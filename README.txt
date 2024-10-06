ELK
Установка база mongo для Elasticserch
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv B00A0BD1E2C63C11 && 
echo "deb [arch=amd64] http://repo.mongodb.org/apt/ubuntu $(lsb_release -sc)/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org.list && 
sudo apt-get update && sudo apt-get install -y mongodb-org &&
sudo systemctl daemon-reload && 
sudo systemctl enable mongod.service && 
sudo systemctl start mongod.service && 
sudo systemctl status mongod.service 
	#установка Elasticserch
wget https://www.techplanet.pro/d/elasticsearch-7.17.1-amd64.deb && 
sudo dpkg -i elasticsearch-7.17.1-amd64.deb &&
	# зделаем память 4G для elasticsearch
sudo echo '-Xms4g' > /etc/elasticsearch/jvm.options.d/xms  && 
sudo echo '-Xmx4g' >> /etc/elasticsearch/jvm.options.d/xms &&	
	#Запустим и проверим elasticsearch
sudo systemctl daemon-reload && 
sudo systemctl enable elasticsearch.service && 
sudo systemctl restart elasticsearch.service && 
sudo systemctl status elasticsearch.service
	# проверим курлом
netstat -tulnp | grep 9200	
curl localhost:9200
	#Установка Logstash
wget  https://www.techplanet.pro/d/logstash-7.17.1-amd64.deb &&
dpkg -i logstash-7.17.1-amd64.deb &&
systemctl enable logstash.service &&
	#----------Настойка-------Logstash-------------------------------------
	#Нам потребуются следующие значения path.config: /etc/logstash/conf.d
sudo sed -i 's/# path.config:/path.config: \/etc\/logstash\/conf.d/g' /etc/logstash/logstash.yml
	#Cгенерируем SSL-сертификат и дадим на него права пользователю logstash	
sudo mkdir -p /etc/elk-certs &&	
cd /etc/elk-certs &&
sudo openssl req -subj '/CN=logstash-server.local/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout elk-ssl.key -out elk-ssl.crt &&
sudo chown logstash elk-ssl.crt &&           
sudo chown logstash elk-ssl.key	
	#Создаем конфиг 
sudo bash -c 'cat > /etc/logstash/conf.d/logstash-nginx-es.conf <<EOF
input {
    beats {
        port => 9600
        ssl => true
        ssl_certificate_authorities => ["/etc/elk-certs/elk-ssl.crt"]
        ssl_certificate => "/etc/elk-certs/elk-ssl.crt"
        ssl_key => "/etc/elk-certs/elk-ssl.key"
        ssl_verify_mode => "force_peer"
    }
}

filter {
 grok {
   match => [ "message" , "%{COMBINEDAPACHELOG}+%{GREEDYDATA:extra_fields}"]
   overwrite => [ "message" ]
 }
 mutate {
   convert => ["response", "integer"]
   convert => ["bytes", "integer"]
   convert => ["responsetime", "float"]
 }
 geoip {
   source => "clientip"
   add_tag => [ "nginx-geoip" ]
 }
 date {
   match => [ "timestamp" , "dd/MMM/YYYY:HH:mm:ss Z" ]
   remove_field => [ "timestamp" ]
 }
 useragent {
   source => "agent"
 }
}

output {
 elasticsearch {
   hosts => ["localhost:9200"]
   index => "weblogs-%{+YYYY.MM.dd}"
   document_type => "nginx_logs"
 }
 stdout { codec => rubydebug }
}
EOF'
	# проверить конфигурацию logstash
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
#on Result: OK. Exiting Logstash
while (! netstat -tulpn | grep 9600) ; do sleep 1; done
	#Далее следует включить автозагрузку и перезапустить службу: Проверить, что служба запущена
sudo systemctl enable logstash &&
sudo systemctl start logstash.service &&
sudo systemctl status logstash.service	
	#установка Kibana
wget https://www.techplanet.pro/d/kibana-7.17.1-amd64.deb &&
dpkg -i kibana-7.17.1-amd64.deb	&&
cp /etc/kibana/kibana.yml  /etc/kibana/kibana.yml.bak &&
sed -i 's/^#network.host:.*/network.host: 0.0.0.0/' /etc/elasticsearch/elasticsearch.yml &&
sed -i 's/^#discovery.seed_hosts:.*/discovery.seed_hosts: []/' /etc/elasticsearch/elasticsearch.yml &&
sudo systemctl restart elasticsearch.service &&
sed -i 's/^#server.host:.*/server.host: "0.0.0.0"/' /etc/kibana/kibana.yml &&
sed -i 's|^#elasticsearch.hosts:.*|elasticsearch.hosts: ["http://51.250.45.63:9200"]|' /etc/kibana/kibana.yml &&
sudo bash -c 'cat > /etc/kibana/kibana.yml <<EOF
server.port: 5601
server.host: 51.250.45.63
elasticsearch.hosts: ["http://localhost:9200"]
logging.dest: /var/log/kibana/kibana.log
logging.rotate:
   enabled: true
   everyBytes: 10485760
   keepFiles: 10
server.basePath: ""
elasticsearch.ssl.certificate: /etc/kibana/crt/elk-ssl.crt
elasticsearch.ssl.key: /etc/kibana/crt/elk-ssl.key
elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/crt/elk-ssl.crt" ]
EOF'
sudo systemctl enable kibana.service &&        
sudo systemctl restart kibana.service &&
sudo systemctl status kibana.service
	# http://51.250.45.63:5601/        h
sudo apt install nginx -y
sudo unlink /etc/nginx/sites-enabled/default	
sudo bash -c 'cat > /etc/nginx/sites-available/51.250.45.63.nip.io.conf <<EOF
server {
        listen 80 default_server;
        server_name 51.250.45.63.nip.io;
		auth_basic "Restricted Access";
		auth_basic_user_file /etc/nginx/htpasswd.users;

		location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF'
sudo ln -s /etc/nginx/sites-available/51.250.45.63.nip.io.conf /etc/nginx/sites-enabled/51.250.45.63.nip.io.conf &&	
echo "elastic:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users &&
	# admin:$apr1$./YtAKWQ$SOkEFs5U7yBznruTfsMlH0  admin   elastic:$apr1$PvNpoX4b$wIn3anQ4Ro2yfvh5E73rM.
sudo unlink /etc/nginx/sites-enabled/default &&
sudo chown www-data:www-data -R /etc/nginx &&
sudo systemctl enable nginx  &&
sudo nginx -t &&
sudo systemctl restart nginx &&
sudo systemctl status nginx
 http://51.250.45.63.nip.io
	#Установка filebeat #apt --purge remove filebeat -y------------------------------------
wget  https://www.techplanet.pro/d/filebeat-7.17.1-amd64.deb &&
dpkg -i filebeat-7.17.1-amd64.deb &&
	#После установки скопируйте файл /etc/filebeat/filebeat.yml
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak &&
	# Отключаем передачу в elasticsearch и включаем в logstash
	# настроим  /etc/filebeat/filebeat.yml
sudo bash -c 'cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.config.modules:
    enabled: true

    path: ${path.config}/modules.d/*.yml

output.elasticsearch:
  hosts: ["localhost:9200"]
  ssl.certificate_authorities: ["/etc/elk-certs/elk-ssl.crt"]
  ssl.certificate: "/etc/elk-certs/elk-ssl.crt"
  ssl.key: "/etc/elk-certs/elk-ssl.key"
  
  setup.kibana:
    host: "51.250.45.63:5601"  
#filebeat.inputs:
#- type: log
#  paths:
#    - /var/log/nginx/*.log
#  exclude_files: ['\.gz$']
#
#output.logstash:
#  hosts: ["localhost:5400"]
EOF'	
filebeat test config
	#Запустим
systemctl restart filebeat
sudo systemctl enable filebeat
systemctl status filebeat	
filebeat test config
	#писок включенных и отключенных модулей с помощью следующей команды
sudo filebeat modules list
	#включить  модули
cd /etc/filebeat	
filebeat modules enable nginx mongodb system
filebeat modules enable elasticsearch logstash kibana
	# настройка модуля mysql
vi /etc/filebeat/modules.d	
- module: mysql
  # Error logs
  error:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    var.paths: ["/var/log/mysql/error.log*"]

  # Slow logs
  slowlog:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    #var.paths:
	# применим конфигурацию
filebeat setup -e
