#!/bin/bash
set -euo pipefail

function prompt() {
    while true; do
        read -p "$1 [y/N] " yn
        case $yn in
            [Yy] ) return 0;;
            [Nn]|"" ) return 1;;
        esac
    done
}

if [[ $(id -u) != 0 ]]; then
    echo Please run this script as root.
    exit 1
fi

if [[ $(uname -m 2> /dev/null) != x86_64 ]]; then
    echo Please run this script on x86_64 machine.
    exit 1
fi

NAME=trojan-go
VERSION=$(curl -fsSL https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | grep tag_name | sed -E 's/.*"v(.*)".*/\1/')
[ -z "$VERSION" ] && VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/p4gefau1t/trojan-go/releases/latest | awk -F '/' '{print $8}' | sed -E 's/.*v(.*).*/\1/')
TARBALL="trojan-go-linux-amd64.zip"
DOWNLOADURL="https://github.com/p4gefau1t/$NAME/releases/download/v$VERSION/$TARBALL"
TMPDIR="$(mktemp -d)"
SYSTEMDPREFIX=/etc/systemd/system
USRSHAREPREFIX=/usr/share

BINARYPATH="/usr/bin/$NAME"
CONFIGPATH="/etc/$NAME/config.json"
SYSTEMDPATH="$SYSTEMDPREFIX/$NAME.service"
GEOIPPATH="$USRSHAREPREFIX/$NAME/geoip.dat"
GEOSITEPATH="$USRSHAREPREFIX/$NAME/geosite.dat"

echo "Initializing. . ."

echo "Obtaining the latest stable version of trojan-go. . ."
[ -z "$VERSION" ] && echo "Failed to obtain, please try again!" && exit 1
echo "Latest stable version:" v${VERSION}

echo "Obtaining public IP. . ."
PUBLICIP=$(dig TXT +short o-o.myaddr.l.google.com @ns.google.com | awk -F'"' '{ print $2}')
if  [[ -z "$PUBLICIP" ]] ; then
    read -p "Failed to obtain, please enter the public IP manually:" PUBLICIP
else
    echo "Public IP:" ${PUBLICIP}
fi

read -p "Please enter your domain name, ex: vpn.abc.com:" DOMAINNAME
[ -z "$DOMAINNAME" ] && echo "Domain name cannot be empty" && exit 1

read -p "Please enter the E-Mail address used to apply for the SSL certificate:" EMAIL
[ -z "$EMAIL" ] && echo "E-Mail address cannot be empty" && exit 1

read -p "Please enter the trojan-go password:" TROJANGOPASSWORD
[ -z "$TROJANGOPASSWORD" ] && echo "trojan-go password cannot be empty" && exit 1

# read -p "Please enter the AccessKey ID:" ALI_KEY
# [ -z "$ALI_KEY" ] && echo "AccessKey ID cannot be empty" && exit 1

# read -p "Please enter the AccessKey Secret:" ALI_SECRET
# [ -z "$ALI_SECRET" ] && echo "AccessKey Secret cannot be empty" && exit 1

echo -e "\n--------You select the information------------"
echo "trojan-go : v$VERSION"
echo "Server IP : $PUBLICIP"
echo "Domain name : $DOMAINNAME"
echo "E-Mall : $EMAIL"
echo "trojan-go password : $TROJANGOPASSWORD"
# echo "AccessKey ID : $ALI_KEY"
# echo "AccessKey Secret : $ALI_SECRET"
echo -e "----------------------------------------------\n"

if [ "$(dig $DOMAINNAME +short | awk 'END {print}')" != "$PUBLICIP" ];then
   echo "Domain name resolution has not yet taken effect, please try again later!"
   exit 1
fi

prompt "Please confirm the configuration information and whether to install it?" $? -eq 0 || exit 1

#创建服务账户
groupadd -f certusers
useradd -r -M -G certusers trojan || echo "User already exists."
useradd -r -m -G certusers acme || echo "User already exists."


#安装acme.sh Trojan需要的依赖
apt install -y cron socat curl unzip
#启动crontab
systemctl start crond
systemctl enable crond

#安装Nginx
apt install -y nginx

#从备份恢复
if [ -f "/etc/nginx/nginx.conf.bak996" ] ; then
    rm /etc/nginx/nginx.conf
    bash -c 'cat /etc/nginx/nginx.conf.bak996 >> /etc/nginx/nginx.conf'
else
    #备份nginx配置文件
    bash -c 'cat /etc/nginx/nginx.conf >> /etc/nginx/nginx.conf.bak996'
fi

#关闭默认虚拟主机
sed -i "37,54s/^/#/" /etc/nginx/nginx.conf
sed -i '/conf.d\/\*.conf/a\    include \/etc\/nginx\/sites-enabled\/\*;' /etc/nginx/nginx.conf
[ -d "/etc/nginx/sites-available" ] || mkdir /etc/nginx/sites-available
[ -d "/etc/nginx/sites-enabled" ] || mkdir /etc/nginx/sites-enabled

#CentOS反向代理需要配置SELinux允许httpd模块可以联网 否则服务器会返回502错误
setsebool -P httpd_can_network_connect true

# Ubuntu or Debian 使用如下命令关闭Nginx默认虚拟主机
# rm /etc/nginx/sites-enabled/default

# 写入虚拟主机到Nginx配置文件
[ -f "/etc/nginx/sites-available/$DOMAINNAME" ] && rm /etc/nginx/sites-available/$DOMAINNAME
cat > "/etc/nginx/sites-available/$DOMAINNAME" << EOF
server {
   listen 127.0.0.1:80 default_server;

   server_name $DOMAINNAME;

   location / {
       root /usr/share/nginx/html;
       index index.html index.htm index.nginx-debian.html;
   }

}

server {
   listen 127.0.0.1:80;

   server_name $PUBLICIP;

   return 301 https://${DOMAINNAME}\$request_uri;
}

server {
   listen 0.0.0.0:80;
   listen [::]:80;

   server_name _;

   location / {
       return 301 https://\$host\$request_uri;
   }

   location /.well-known/acme-challenge {
      root /var/www/acme-challenge;
   }
}
EOF

#使能配置文件
[ -L "/etc/nginx/sites-enabled/$DOMAINNAME" ] || ln -s /etc/nginx/sites-available/$DOMAINNAME /etc/nginx/sites-enabled/
systemctl enable nginx
systemctl restart nginx
systemctl status --no-pager nginx

#创建证书文件夹
[ -d "/etc/letsencrypt/live" ] || mkdir -p /etc/letsencrypt/live
chown -R acme:acme /etc/letsencrypt/live

#查找nginx: worker process所属用户
NGINXUSER=$(ps -eo user,command | grep nginx | awk 'NR==2{print$1}')
usermod -G certusers $NGINXUSER

#运行下面两条命令，第一条命令新建一个文件夹/var/www/acme-challenge用于给acme.sh存放域名验证文件。第二条命令将证书文件夹所有者改为acme 使得用户acme有权限写入文件 同时当验证的时候Nginx可以读取该文件。
[ -d "/var/www/acme-challenge" ] || mkdir -p  /var/www/acme-challenge
chown -R acme:certusers /var/www/acme-challenge

#安装acme.sh自动管理CA证书脚本
su -l -s /bin/bash acme << EOF
curl https://get.acme.sh | sh -s email=$EMAIL
EOF

#export Ali_Key="$ALI_KEY"
#export Ali_Secret="$ALI_SECRET"
#~/.acme.sh/acme.sh --issue --dns dns_ali -d $DOMAINNAME -w /var/www/acme-challenge
su -l -s /bin/bash acme << EOF
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d $DOMAINNAME -w /var/www/acme-challenge
~/.acme.sh/acme.sh --install-cert -d $DOMAINNAME --key-file /etc/letsencrypt/live/${DOMAINNAME}-private.key --fullchain-file /etc/letsencrypt/live/${DOMAINNAME}-certificate.crt
~/.acme.sh/acme.sh --info -d $DOMAINNAME
~/.acme.sh/acme.sh --upgrade --auto-upgrade
chown -R acme:certusers /etc/letsencrypt/live
chmod -R 750 /etc/letsencrypt/live
EOF

#重载nginx
systemctl restart nginx

#安装Trojan
echo Entering temp directory $TMPDIR...
cd "$TMPDIR"

echo Downloading $NAME $VERSION...
curl -LO --progress-bar "$DOWNLOADURL" || wget -q --show-progress "$DOWNLOADURL"

echo Unpacking $NAME $VERSION...
unzip "$TARBALL"

echo Installing $NAME $VERSION to $BINARYPATH...
install -Dm755 "$NAME" "$BINARYPATH"

echo Installing $NAME server config to $CONFIGPATH...
if ! [[ -f "$CONFIGPATH" ]] || prompt "The server config already exists in $CONFIGPATH, overwrite?"; then
    sed -i "s/your_password/$TROJANGOPASSWORD/" example/server.json
    sed -i "s/your_cert.crt/\/etc\/letsencrypt\/live\/${DOMAINNAME}-certificate.crt/" example/server.json
    sed -i "s/your_key.key/\/etc\/letsencrypt\/live\/${DOMAINNAME}-private.key/" example/server.json
    sed -i "s/your-domain-name.com/${DOMAINNAME}/" example/server.json
    install -Dm644 example/server.json "$CONFIGPATH"
    chown -R trojan:trojan $CONFIGPATH
else
    echo Skipping installing $NAME server config...
fi

echo Installing $NAME geoip.dat to $GEOIPPATH...
if ! [[ -f "$GEOIPPATH" ]] || prompt "The ggeoip.dat already exists in $GEOIPPATH, overwrite?"; then
    install -Dm644 geoip.dat "$GEOIPPATH"
    chown -R trojan:trojan $GEOIPPATH
else
    echo Skipping installing $NAME geoip.dat...
fi

echo Installing $NAME geosite.dat to $GEOSITEPATH...
if ! [[ -f "$GEOSITEPATH" ]] || prompt "The geosite.dat already exists in $GEOSITEPATH, overwrite?"; then
    install -Dm644 geosite.dat "$GEOSITEPATH"
    chown -R trojan:trojan $GEOSITEPATH
else
    echo Skipping installing $NAME geosite.dat...
fi

if [[ -d "$SYSTEMDPREFIX" ]]; then
    echo Installing $NAME systemd service to $SYSTEMDPATH...
    if ! [[ -f "$SYSTEMDPATH" ]] || prompt "The systemd service already exists in $SYSTEMDPATH, overwrite?"; then
        sed -i 's/nobody/trojan/' example/trojan-go.service
        install -Dm644 example/trojan-go.service "$SYSTEMDPATH"
        echo Reloading systemd daemon...
        systemctl daemon-reload
    else
        echo Skipping installing $NAME systemd service...
    fi
fi

echo Deleting temp directory $TMPDIR...
rm -rf "$TMPDIR"

echo Done!

#赋予Trojan监听443端口能力
setcap CAP_NET_BIND_SERVICE=+eip $BINARYPATH

#使用systemd启动Trojan
systemctl enable trojan-go
systemctl restart trojan-go
systemctl status --no-pager trojan-go

echo "0 0 1 * * killall -s SIGUSR1 trojan" >> /var/spool/cron/trojan
chown -R trojan:trojan /var/spool/cron/trojan

sudo -u trojan crontab -l
sudo -u acme crontab -l

echo -e "\n--------your server information------------"
echo "trojan-go : v$VERSION"
echo "Domain name : $DOMAINNAME"
echo "trojan-go password : $TROJANGOPASSWORD"
echo -e "----------------------------------------------\n"
