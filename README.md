# trojan-go quickstart

A simple installation script for trojan-go server.  
trojan-go 服务器的简单安装脚本。

This script will help you install the trojan-go binary to `/usr/bin`, a template for server configuration to `/usr/etc/trojan`, and (if applicable) a systemd service to `/etc/systemd/system`. It only works on `linux-amd64` machines.  
该脚本将帮助您将 trojan-go 二进制文件安装到“/usr/bin”，将服务器配置模板安装到“/usr/etc/trojan”，以及（如果适用）将 systemd 服务安装到“/etc/systemd/system” `。 它仅适用于“linux-amd64”机器。

Special reminder, this program will automatically install and configure Nginx and trojan-go, and automatically apply for an SSL certificate. Therefore, it is recommended to deploy on a new server without nginx installed.  
特别提醒，本程序会自动安装并配置Nginx和trojan-go，自动申请ssl证书。所以建议在未安装nginx的全新服务器上部署。

## Preparation
| Parameter | Description |
| --- | --- |
| Public IP | The public IP of the current server |
| Domain name | The domain name used by the client to connect to the server needs to be resolved to the public IP of the server in advance |
| Email address | used to apply for SSL certificate |
| VPN password | It is recommended to add letters and numbers, 8 digits |

## 准备工作
| 参数 | 描述 |
| --- | --- |
| 公网IP | 该服务器的公网IP |
| 域名 | 客户端连接服务器使用的域名，需要提前解析到该服务器的公网IP上 |
| 邮箱地址 | 用于申请SSL证书 |
| VPN密码 | 建议添加字母和数字，8位数字 |

## Usage 

- via `curl`
    ```
    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/GoodyOG/trojan-go-quickstart/master/trojan-go-quickstart.sh)"
    ```
- via `wget`
    ```
    sudo bash -c "$(wget -O- https://raw.githubusercontent.com/GoodyOG/trojan-go-quickstart/master/trojan-go-quickstart.sh)"
    ```
