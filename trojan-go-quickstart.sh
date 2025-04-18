#!/bin/bash
set -euo pipefail

# Function to prompt for confirmation
function prompt() {
    while true; do
        read -p "$1 [y/N] " yn
        case $yn in
            [Yy] ) return 0;;
            [Nn]|"" ) return 1;;
        esac
    done
}

# Check if running as root
if [[ $(id -u) != 0 ]]; then
    echo "Please run this script as root."
    exit 1
fi

# Check if system is x86_64
if [[ $(uname -m) != x86_64 ]]; then
    echo "Please run this script on an x86_64 machine."
    exit 1
fi

# Define variables
NAME="trojan-go"
VERSION=$(curl -fsSL https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' || true)
[ -z "$VERSION" ] && VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/p4gefau1t/trojan-go/releases/latest | awk -F '/' '{print $8}' | sed -E 's/.*v(.*).*/\1/')
TARBALL="trojan-go-linux-amd64.zip"
DOWNLOADURL="https://github.com/p4gefau1t/$NAME/releases/download/v$VERSION/$TARBALL"
TMPDIR="$(mktemp -d)"
SYSTEMDPREFIX="/etc/systemd/system"
USRSHAREPREFIX="/usr/share"
BINARYPATH="/usr/bin/$NAME"
CONFIGPATH="/etc/$NAME/config.json"
SYSTEMDPATH="$SYSTEMDPREFIX/$NAME.service"
GEOIPPATH="$USRSHAREPREFIX/$NAME/geoip.dat"
GEOSITEPATH="$USRSHAREPREFIX/$NAME/geosite.dat"

echo "Initializing..."

# Verify version
[ -z "$VERSION" ] && { echo "Failed to obtain Trojan-Go version. Check network or GitHub API."; exit 1; }
echo "Latest stable version: v${VERSION}"

# Get public IP
PUBLICIP=$(dig TXT +short o-o.myaddr.l.google.com @ns.google.com | awk -F'"' '{ print $2}' || true)
if [[ -z "$PUBLICIP" ]]; then
    read -p "Failed to obtain public IP, please enter it manually: " PUBLICIP
else
    echo "Public IP: ${PUBLICIP}"
fi

# Get user input
read -p "Please enter your domain name (e.g., vpn.example.com): " DOMAINNAME
[ -z "$DOMAINNAME" ] && { echo "Domain name cannot be empty."; exit 1; }

read -p "Please enter the E-Mail address for SSL certificate: " EMAIL
[ -z "$EMAIL" ] && { echo "E-Mail address cannot be empty."; exit 1; }

read -p "Please enter the Trojan-Go password: " TROJANGOPASSWORD
[ -z "$TROJANGOPASSWORD" ] && { echo "Trojan-Go password cannot be empty."; exit 1; }

# Display configuration
echo -e "\n-------- Configuration ------------"
echo "Trojan-Go : v$VERSION"
echo "Server IP : $PUBLICIP"
echo "Domain name : $DOMAINNAME"
echo "E-Mail : $EMAIL"
echo "Trojan-Go password : $TROJANGOPASSWORD"
echo -e "-----------------------------------\n"

# Verify domain resolves to public IP
if [[ "$(dig +short $DOMAINNAME | tail -n 1)" != "$PUBLICIP" ]]; then
    echo "Domain name resolution does not match public IP. Please ensure DNS is configured."
    exit 1
fi

prompt "Please confirm the configuration and proceed with installation?" || exit 1

# Install dependencies
echo "Installing dependencies..."
sudo apt update
sudo apt install -y cron socat curl unzip nginx || { echo "Failed to install dependencies."; exit 1; }

# Start and enable cron
sudo systemctl enable cron --now || { echo "Failed to enable/start cron."; exit 1; }

# Create service accounts
echo "Creating service accounts..."
groupadd -f certusers
useradd -r -M -G certusers -s /usr/sbin/nologin trojan 2>/dev/null || echo "User trojan already exists."
useradd -r -m -G certusers -s /bin/bash acme 2>/dev/null || echo "User acme already exists."

# Configure Nginx
echo "Configuring Nginx..."
# Backup Nginx configuration
[ -f "/etc/nginx/nginx.conf.bak" ] || cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

# Ensure sites-available and sites-enabled directories exist
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# Remove default site and any conflicting configurations
[ -f "/etc/nginx/sites-enabled/default" ] && rm /etc/nginx/sites-enabled/default
[ -f "/etc/nginx/sites-enabled/$DOMAINNAME" ] && rm /etc/nginx/sites-enabled/$DOMAINNAME

# Create Nginx configuration for HTTP-01 challenge
cat > "/etc/nginx/sites-available/$DOMAINNAME" << EOF
server {
    listen 127.0.0.1:80;
    listen 0.0.0.0:80;
    listen [::]:80;
    server_name $DOMAINNAME $PUBLICIP;

    location /.well-known/acme-challenge {
        root /var/www/acme-challenge;
        allow all;
    }

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
    }
}
EOF

# Enable the configuration
ln -sf /etc/nginx/sites-available/$DOMAINNAME /etc/nginx/sites-enabled/$DOMAINNAME

# Fix permissions for acme-challenge directory
mkdir -p /var/www/acme-challenge
chown -R acme:certusers /var/www/acme-challenge
chmod -R 755 /var/www/acme-challenge

# Add Nginx user to certusers group
NGINXUSER="www-data"
usermod -aG certusers $NGINXUSER

# Test Nginx configuration
sudo nginx -t || { echo "Nginx configuration test failed."; exit 1; }

# Start and enable Nginx
sudo systemctl enable nginx --now || { echo "Failed to enable/start Nginx."; exit 1; }

# Configure firewall
echo "Configuring firewall..."
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload

# Install acme.sh and issue SSL certificate using HTTP-01 challenge
echo "Installing acme.sh and issuing SSL certificate..."
sudo su - acme -c "curl https://get.acme.sh | sh -s email=$EMAIL" || { echo "Failed to install acme.sh."; exit 1; }
sudo su - acme -c "~/.acme.sh/acme.sh --set-default-ca --server letsencrypt" || { echo "Failed to set Let’s Encrypt as CA."; exit 1; }
sudo su - acme -c "~/.acme.sh/acme.sh --issue -d $DOMAINNAME -w /var/www/acme-challenge --force" || { echo "Failed to issue SSL certificate."; exit 1; }
sudo su - acme -c "~/.acme.sh/acme.sh --install-cert -d $DOMAINNAME \
    --key-file /etc/letsencrypt/live/${DOMAINNAME}-private.key \
    --fullchain-file /etc/letsencrypt/live/${DOMAINNAME}-certificate.crt" || { echo "Failed to install SSL certificate."; exit 1; }
sudo su - acme -c "~/.acme.sh/acme.sh --upgrade --auto-upgrade" || { echo "Failed to enable auto-upgrade for acme.sh."; exit 1; }

# Fix certificate permissions
mkdir -p /etc/letsencrypt/live
chown -R acme:certusers /etc/letsencrypt/live
chmod -R 750 /etc/letsencrypt/live

# Install Trojan-Go
echo "Installing Trojan-Go..."
cd "$TMPDIR"
curl -LO --progress-bar "$DOWNLOADURL" || wget -q --show-progress "$DOWNLOADURL" || { echo "Failed to download Trojan-Go."; exit 1; }
unzip "$TARBALL" || { echo "Failed to unzip Trojan-Go."; exit 1; }

# Install binary
install -Dm755 "$NAME" "$BINARYPATH"

# Install server configuration
if [[ ! -f "$CONFIGPATH" ]] || prompt "Config $CONFIGPATH exists, overwrite?"; then
    mkdir -p /etc/$NAME
    cat > "$CONFIGPATH" << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["$TROJANGOPASSWORD"],
    "ssl": {
        "cert": "/etc/letsencrypt/live/${DOMAINNAME}-certificate.crt",
        "key": "/etc/letsencrypt/live/${DOMAINNAME}-private.key",
        "sni": "$DOMAINNAME"
    }
}
EOF
    chown trojan:trojan "$CONFIGPATH"
    chmod 640 "$CONFIGPATH"
fi

# Install geoip and geosite data
if [[ ! -f "$GEOIPPATH" ]] || prompt "GeoIP $GEOIPPATH exists, overwrite?"; then
    install -Dm644 geoip.dat "$GEOIPPATH"
    chown trojan:trojan "$GEOIPPATH"
fi
if [[ ! -f "$GEOSITEPATH" ]] || prompt "GeoSite $GEOSITEPATH exists, overwrite?"; then
    install -Dm644 geosite.dat "$GEOSITEPATH"
    chown trojan:trojan "$GEOSITEPATH"
fi

# Install systemd service
if [[ ! -f "$SYSTEMDPATH" ]] || prompt "Systemd service $SYSTEMDPATH exists, overwrite?"; then
    cat > "$SYSTEMDPATH" << EOF
[Unit]
Description=Trojan-Go - A Trojan proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/trojan-go -config /etc/$NAME/config.json
Restart=on-failure
User=trojan
Group=trojan
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi

# Clean up
rm -rf "$TMPDIR"

# Allow Trojan-Go to bind to port 443
setcap CAP_NET_BIND_SERVICE=+eip "$BINARYPATH" || { echo "Failed to set capabilities for Trojan-Go."; exit 1; }

# Start and enable Trojan-Go
systemctl enable trojan-go --now || { echo "Failed to enable/start Trojan-Go."; exit 1; }

# Set up cron job for Trojan-Go
echo "0 0 1 * * /usr/bin/killall -s SIGUSR1 trojan-go" | sudo -u trojan crontab -

# Verify services
echo "Verifying services..."
systemctl status --no-pager nginx trojan-go

# Display final information
echo -e "\n-------- Server Information ------------"
echo "Trojan-Go : v$VERSION"
echo "Domain name : $DOMAINNAME"
echo "Trojan-Go password : $TROJANGOPASSWORD"
echo "SSL certificates: /etc/letsencrypt/live/$DOMAINNAME"
echo -e "-----------------------------------\n"

echo "Installation complete!"
