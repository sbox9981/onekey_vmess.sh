#/bin/bash

source /etc/os-release
cd /root

start_menu(){
clear
echo
echo -e "\t1. 安装v2ray"
echo -e "\t2. 修改域名"
echo -e "\t3. 更新ssl证书"
echo -e "\t4. 查看客户端文件"
echo -e "\t5. 更新v2ray"
echo -e "\t6. 重启服务"
echo -e "\t7. 查看vmess链接"
echo -e "\t8. 卸载v2ray"
echo
read -p "请输入数字：" ini
case $ini in
1)
V2RAY_VAR
SYSTEM_CONFIG
DOMAIN_KEY
TIME_UPDATE
NGINX_INSTALL
V2RAY_INSTALLl
V2RAY_CONFIG
NGINX_CONFIG
CLIENT_CONFIG
VMESS_LINK
;;
2)
rm -rf /root/v2ray/v2ray.ini
V2RAY_VAR
DOMAIN_KEY
V2RAY_CONFIG
NGINX_CONFIG
CLIENT_CONFIG
VMESS_LINK
;;
3)
DOMAIN_KEY
RESTART_V2RAY
;;
4)
CLIENT_CONFIG
cat /root/v2ray/config.json
;;

5)
V2RAY_INSTALLl
RESTART_V2RAY
echo "v2ray已更新"
v2ray -version
;;
6)
RESTART_V2RAY
;;
7)
VMESS_LINK
;;
8)
REMOVE_V2RAY
;;
*)
clear
echo -e "请输入数字："
start_menu
;;
esac
}

V2RAY_VAR(){
case $ID in
  arch|manjaro)
  if ! [ -x "$(command -v curl)"  ] ; then
   pacman -S curl --noconfirm
  fi
  ;;
  ubuntu|debian|deepin)
  if ! [ -x "$(command -v curl)"  ] ; then
   apt install curl -y
  fi
  ;;
  centos|fedora|rhel)
  yumdnf="yum"
  if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
  yumdnf="dnf"
  fi
  if ! [ -x "$(command -v curl)"  ] ; then
   $yumdnf install curl -y
  fi
  ;;
  *)
  exit
  ;;
esac


mkdir -p /root/v2ray
read -p "请输入域名:" name
name_ecc=$(echo $name\_ecc)

#检测是否解析成功
domain_ip=$(ping "${name}" -c 5 | sed '1{s/[^(]*(//;s/).*//;q}')
echo "域名解析ip为：$domain_ip"
echo "$domain_ip" >dip.log
local_ip=$(curl -4 ip.sb)
echo "本机IP为：$local_ip"
echo "$local_ip" >lip.log

ip=`diff dip.log lip.log`

if [ "$ip" = "" ] ; then
echo "解析成功"
echo dname=$name >> /root/v2ray/v2ray.ini
echo name_ecc=$name_ecc >> /root/v2ray/v2ray.ini
rm -rf dip.log lip.log
else
echo "解析不成功。。。"
rm -rf dip.log lip.log
exit 0
fi

#设置环境变量
uuid=$(cat /proc/sys/kernel/random/uuid)
echo uuid=$uuid >> /root/v2ray/v2ray.ini
path=$(head -c 100 /dev/urandom | tr -dc a-z0-9A-Z |head -c 7)
echo path=$path >> /root/v2ray/v2ray.ini
}

#系统优化
SYSTEM_CONFIG(){

#禁用seLinux
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
setenforce 0
fi


#优化内核参数
cat >> /etc/sysctl.conf <<-'EOF'
fs.file-max = 1024000
fs.inotify.max_user_instances = 8192
net.core.default_qdisc=fq
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 8388608
net.core.rmem_max = 67108864
net.core.somaxconn = 65535
net.core.wmem_default = 8388608
net.core.wmem_max = 67108864
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_congestion_control = hybla
# hybla适合美国等高延迟，htcp适合日本等低延迟
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 60000
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_sack = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 4096 65536 67108864
EOF
sysctl -p
sed -i '1a\sysctl -p' /etc/rc.local

#其他优化
echo "ulimit -SHn 1024000" >> /etc/profile

cat >> /etc/security/limits.conf <<-'EOF'
* soft nproc 1000000
* hard nproc 1000000
* soft nofile 1000000
* hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF

echo "session required pam_limits.so" >>/etc/pam.d/common-session

case $ID in
  arch|manjaro)
  if ! [ -x "$(command -v lsb-release)"  ] ; then
 pacman -S lsb-release --noconfirm
  fi
  ;;
  debian|ubuntu|devuan)
  if ! [ -x "$(command -v lsb-release)"  ] ; then
   apt-get install lsb-release
  fi
  ;;
  centos|fedora|rhel)
  yum install bc
  yumdnf="yum"
  if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
  yumdnf="dnf"
  fi
  if ! [ -x "$(command -v redhat-lsb-core)"  ] ; then
   $yumdnf install -y redhat-lsb-core
  fi
  ;;
  *)
  exit
  ;;
esac

}

#时间同步
TIME_UPDATE(){

case $ID in
  arch|manjaro)
  if ! [ -x "$(command -v ntpdate)"  ] ; then
   pacman -S ntpdate --noconfirm
  rm -rf /etc/localtime
  ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  hwclock --systohc --utc
  fi
  ;;
  ubuntu|debian|deepin)
  if ! [ -x "$(command -v ntpdate)"  ] ; then
   apt install ntpdate -y
  rm -rf /etc/localtime
  ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  ntpdate us.pool.ntp.org
  fi
  ;;
  centos|fedora|rhel)
  yumdnf="yum"
  if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
  yumdnf="dnf"
  fi
  if ! [ -x "$(command -v chrony)"  ] ; then
   $yumdnf install chrony -y
  fi
  timedatectl set-ntp true
  systemctl enable chronyd && systemctl restart chronyd
  timedatectl set-timezone Asia/Shanghai
  ;;
  *)
  exit
  ;;
  esac
}

# 安装证书
DOMAIN_KEY(){

case $ID in
  arch|manjaro)
  if ! [ -x "$(command -v socat)"  ] ; then
   pacman -S socat --noconfirm
  fi
  ;;
  ubuntu|debian|deepin)
  if ! [ -x "$(command -v socat)"  ] ; then
   apt install socat -y
  fi
  ;;
  centos|fedora|rhel)
  yumdnf="yum"
  if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
  yumdnf="dnf"
  fi
  if ! [ -x "$(command -v socat)"  ] ; then
   $yumdnf install socat -y
  fi
  ;;
  *)
  exit
  ;;
esac

#生成证书
domain_key_name=$(cat /root/v2ray/v2ray.ini|grep dname |cut -f2 -d "=")
domain_key_name_ecc=$(cat /root/v2ray/v2ray.ini|grep name_ecc |cut -f2 -d "=")
if ! [ -d "$HOME/.acme.sh/$domain_key_name_ecc" ] ; then
curl  https://get.acme.sh | sh
source .bashrc
bash /root/.acme.sh/acme.sh --issue -d $domain_key_name --standalone -k ec-256
else
source .bashrc
bash /root/.acme.sh/acme.sh --renew -d $domain_key_name --force --ecc
fi
}

#安装nginx
NGINX_INSTALL(){
case $ID in
  arch|manjaro)
  if ! [ -x "$(command -v nginx)"  ] ; then
   pacman -S nginx --noconfirm
  fi
  ;;
  ubuntu|debian|deepin)
  if ! [ -x "$(command -v nginx)"  ] ; then
   apt install nginx -y
  fi
  ;;
  centos|fedora|rhel)
  yumdnf="yum"
  if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
  yumdnf="dnf"
  fi
  if ! [ -x "$(command -v nginx)"  ] ; then
   rpm -ivh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
   $yumdnf install nginx -y
  fi
  ;;
  *)
  exit
  ;;
esac
}

#安装v2ray
V2RAY_INSTALLl(){
if ! [ -d "$HOME/v2ray/zsxwz" ] ; then
mkdir -p /root/v2ray/zsxwz
cd /root/v2ray/zsxwz  ||exit
wget -O go.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
bash go.sh
cd /root  ||exit
else
cd /root/v2ray/zsxwz  ||exit
bash go.sh
cd /root  ||exit
exit 0
fi
}

#服务端配置文件
V2RAY_CONFIG(){
v2ray_uuid=$(cat /root/v2ray/v2ray.ini|grep uuid |cut -f2 -d "=")
v2ray_path=$(cat /root/v2ray/v2ray.ini|grep path |cut -f2 -d "=")
cat > /usr/local/etc/v2ray/config.json <<-EOF
{
    "log": {
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log",
        "loglevel": "warning"
    },
    "dns": {
        
    },
    "stats": {
        
    },
    "inbounds": [
        {
            "port": 8012,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$v2ray_uuid",
                        "alterId": 64
                    }
                ]
            },
            "tag": "in-0",
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/$v2ray_path/"
                }
            },
            "listen": "127.0.0.1"
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                
            }
        },
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {
                
            }
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "blocked"
            }
        ]
    },
    "policy": {
        
    },
    "reverse": {
        
    },
    "transport": {
        
    }
}
EOF

systemctl daemon-reload
systemctl stop v2ray
systemctl enable v2ray
systemctl start v2ray
}

#nginx配置文件
NGINX_CONFIG(){
case $ID in
  arch|manjaro)
  nginx_config="/etc/nginx/sites-available/default"
  ;;
  ubuntu|debian|deepin)
  nginx_config="/etc/nginx/sites-available/default"
  ;;
  centos|fedora|rhel)
  nginx_config="/etc/nginx/conf.d/default.conf"
  ;;
  *)
  exit
  ;;
esac

nginx_name=$(cat /root/v2ray/v2ray.ini|grep dname |cut -f2 -d "=")
nginx_name_ecc=$(cat /root/v2ray/v2ray.ini|grep name_ecc |cut -f2 -d "=")
nginx_path=$(cat /root/v2ray/v2ray.ini|grep path |cut -f2 -d "=")

mkdir -p /root/wwwroot/html
chmod 777 /root/wwwroot/html

cat > $nginx_config <<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name $nginx_name;
    return 301 https://$nginx_name\$request_uri;
    location /nginx_path {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $nginx_name;
    root /root/wwwroot/html;
    index index.html;

    ssl_certificate       $HOME/.acme.sh/$nginx_name_ecc/fullchain.cer;  
    ssl_certificate_key   $HOME/.acme.sh/$nginx_name_ecc/$nginx_name.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Public-Key-Pins 'pin-sha256="amMeV6gb9QNx0Zf7FtJ19Wa/t2B7KpCF/1n2Js3UuSU="; pin-sha256="6YBE8kK4d5J1qu1wEjyoKqzEIvyRY5HyM/NB2wKdcZo="; max-age=2592000; includeSubDomains';

    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1 valid=60s;
    resolver_timeout 60s;

    location /$nginx_path {
      if (\$http_upgrade != "websocket") {
          return 404;
      }
      proxy_redirect off;
      proxy_pass http://127.0.0.1:8012;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /nginx_status {
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
EOF

cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
sed -i 's/^user.*/user root;/g' /etc/nginx/nginx.conf

wget -O /root/wwwroot/html/html.tar.gz http://www.zsxwz.com/deepin/html.tar.gz
cd /root/wwwroot/html
tar zxvf html.tar.gz
rm -rf html.tar.gz
cd /root

systemctl daemon-reload
systemctl stop nginx
systemctl enable nginx
systemctl start nginx
}


#生成客户端文件
CLIENT_CONFIG(){
client_name=$(cat /root/v2ray/v2ray.ini|grep dname |cut -f2 -d "=")
client_path=$(cat /root/v2ray/v2ray.ini|grep path |cut -f2 -d "=")
client_uuid=$(cat /root/v2ray/v2ray.ini|grep uuid |cut -f2 -d "=")
cat >/root/v2ray/config.json<<-EOF
{
    "log": {
        
    },
    "dns": {
        
    },
    "stats": {
        
    },
    "inbounds": [
        {
            "port": "1080",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true
            },
            "tag": "in-0"
        }
    ],
    "outbounds": [
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "$client_name",
                        "port": 443,
                        "users": [
                            {
                                "id": "$client_uuid",
                                "alterId": 64
                            }
                        ]
                    }
                ]
            },
            "tag": "out-0",
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": "/$client_path/"
                },
                "tlsSettings": {
                    "serverName": "$client_name"
                }
            }
        },
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                
            }
        },
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {
                
            }
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "direct"
            }
        ]
    },
    "policy": {
        
    },
    "reverse": {
        
    },
    "transport": {
        
    }
}
EOF

echo "cat /root/v2ray/config.json即可查看配置文件"
}

#生成vmess链接
VMESS_LINK() {
vmess_uuid=$(cat /root/v2ray/v2ray.ini|grep uuid |cut -f2 -d "=")
vmess_path=$(cat /root/v2ray/v2ray.ini|grep path |cut -f2 -d "=")
vmess_name=$(cat /root/v2ray/v2ray.ini|grep dname |cut -f2 -d "=")
cat >/root/v2ray/.v2ray_config <<-EOF
{
  "v": "2",
  "ps": "${vmess_name}",
  "add": "${vmess_name}",
  "port": "443",
  "id": "${vmess_uuid}",
  "aid": "64",
  "net": "ws",
  "type": "none",
  "host": "${vmess_name}",
  "path": "/${vmess_path}/",
  "tls": "tls"
}
EOF

vmess_link="vmess://$(base64 -w 0 /root/v2ray/.v2ray_config)"

echo "wmess链接："
echo "$vmess_link"
}

#重启服务
RESTART_V2RAY(){
systemctl daemon-reload
systemctl stop v2ray
systemctl start v2ray
systemctl stop nginx
systemctl start nginx
echo "v2ray已重新启动"
}

#卸载
REMOVE_V2RAY(){
systemctl daemon-reload
systemctl stop v2ray
systemctl stop nginx
bash /root/v2ray/zsxwz/go.sh --remove
rm -rf /root/v2ray/zsxwz/go.sh
rm -rf /etc/v2ray /var/log/v2ray /etc/nginx/sites-available/default /root/config.json /root/.acme.sh/ /root/v2ray /root/v2.sh
echo "已卸载"
}

start_menu
