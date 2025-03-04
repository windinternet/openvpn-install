#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.

# 检查是否使用 bash 运行脚本
if readlink /proc/$$/exe | grep -q "dash"; then
    echo "此安装脚本需要使用 'bash' 运行，而不是 'sh'。"
    exit
fi

# 丢弃标准输入（处理包含换行符的单行命令）
read -N 999999 -t 0.001

# 检测操作系统
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
else
    echo "此安装脚本似乎在不受支持的发行版上运行。
支持的发行版包括 Ubuntu、Debian、AlmaLinux、Rocky Linux、CentOS 和 Fedora。"
    exit
fi

# 检查操作系统版本
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    echo "此安装脚本需要 Ubuntu 22.04 或更高版本。
当前 Ubuntu 版本太旧且不受支持。"
    exit
fi

if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        echo "Debian Testing 和 Debian Unstable 不受此安装脚本支持。"
        exit
    fi
    if [[ "$os_version" -lt 11 ]]; then
        echo "此安装脚本需要 Debian 11 或更高版本。
当前 Debian 版本太旧且不受支持。"
        exit
    fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
    os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
    echo "$os_name 9 或更高版本是此安装脚本的要求。
当前 $os_name 版本太旧且不受支持。"
    exit
fi

# 检查 $PATH 是否包含 sbin 目录
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH 不包含 sbin。尝试使用 "su -" 而不是 "su"。'
    exit
fi

# 检查是否以 root 权限运行
if [[ "$EUID" -ne 0 ]]; then
    echo "此安装脚本需要以超级用户权限运行。"
    exit
fi

# 检查 TUN 设备是否可用
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    echo "系统中没有可用的 TUN 设备。
在运行此安装脚本之前需要启用 TUN。"
    exit
fi

# 生成客户端配置文件函数
new_client () {
    {
    cat /etc/openvpn/server/client-common.txt
    echo "<ca>"
    cat /etc/openvpn/server/easy-rsa/pki/ca.crt
    echo "</ca>"
    echo "<cert>"
    sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
    echo "</cert>"
    echo "<key>"
    cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
    echo "</key>"
    echo "<tls-crypt>"
    sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
    echo "</tls-crypt>"
    } > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    # 检查是否安装 wget 或 curl
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo "此安装脚本需要 Wget。"
        read -n1 -r -p "按任意键安装 Wget 并继续..."
        apt-get update
        apt-get install -y wget
    fi
    clear
    echo '欢迎使用 OpenVPN 安装脚本！'
    # 自动选择单个 IPv4 或提示用户选择
    if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
        echo
        echo "请选择要使用的 IPv4 地址："
        ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
        read -p "IPv4 地址 [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
            echo "$ip_number: 无效的选择。"
            read -p "IPv4 地址 [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    fi
    # 如果是私有 IP，提示输入公网 IP 或主机名
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo
        echo "此服务器位于 NAT 后面。请输入公网 IPv4 地址或主机名："
        get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
        read -p "公网 IPv4 地址 / 主机名 [$get_public_ip]: " public_ip
        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
            echo "无效输入。"
            read -p "公网 IPv4 地址 / 主机名: " public_ip
        done
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    fi
    # 自动选择单个 IPv6 或提示用户选择
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    fi
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
        echo
        echo "请选择要使用的 IPv6 地址："
        ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
        read -p "IPv6 地址 [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
            echo "$ip6_number: 无效的选择。"
            read -p "IPv6 地址 [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    fi
    echo
    echo "OpenVPN 应该使用哪种协议？"
    echo "   1) UDP (推荐)"
    echo "   2) TCP"
    read -p "协议 [1]: " protocol
    until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
        echo "$protocol: 无效的选择。"
        read -p "协议 [1]: " protocol
    done
    case "$protocol" in
        1|"")
            protocol=udp
            ;;
        2)
            protocol=tcp
            ;;
    esac
    echo
    echo "OpenVPN 应该监听哪个端口？"
    read -p "端口 [1194]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: 无效的端口。"
        read -p "端口 [1194]: " port
    done
    [[ -z "$port" ]] && port="1194"
    echo
    echo "请选择客户端的 DNS 服务器："
    echo "   1) 当前系统解析器"
    echo "   2) Google"
    echo "   3) 1.1.1.1"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) AdGuard"
    read -p "DNS 服务器 [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
        echo "$dns: 无效的选择。"
        read -p "DNS 服务器 [1]: " dns
    done
    echo
    echo "请输入第一个客户端的名称："
    read -p "名称 [client]: " unsanitized_client
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
    [[ -z "$client" ]] && client="client"
    echo
    echo "OpenVPN 安装即将开始。"
    # 检查并安装防火墙
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
            echo "将安装并启用 firewalld 以管理路由表。"
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        fi
    fi
    read -n1 -r -p "按任意键继续..."
    # 如果在容器中运行，禁用 LimitNPROC
    if systemd-detect-virt -cq; then
        mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
        echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
    fi
    # 安装 OpenVPN 和相关组件
    if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
        apt-get update
        apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
    elif [[ "$os" = "centos" ]]; then
        dnf install -y epel-release
        dnf install -y openvpn openssl ca-certificates tar $firewall
    else
        dnf install -y openvpn openssl ca-certificates tar $firewall
    fi
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld.service
    fi
    # 获取 EasyRSA，适配中国网络环境
    easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.2/EasyRSA-3.2.2.tgz'
    easy_rsa_mirror='https://ghproxy.com/https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.2/EasyRSA-3.2.2.tgz' # 国内镜像
    mkdir -p /etc/openvpn/server/easy-rsa/
    if ! { wget -qO- "$easy_rsa_mirror" 2>/dev/null || curl -sL "$easy_rsa_mirror" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1; then
        if ! { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1; then
            echo "错误: 无法从 $easy_rsa_url 或镜像下载 EasyRSA。" >&2
            echo "请手动下载 EasyRSA-3.2.2.tgz 并放置到 /etc/openvpn/server/easy-rsa/ 目录下，然后解压。" >&2
            echo "下载地址: $easy_rsa_url" >&2
            echo "命令示例: tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1 -f EasyRSA-3.2.2.tgz" >&2
            exit 1
        fi
    fi
    chown -R root:root /etc/openvpn/server/easy-rsa/
    cd /etc/openvpn/server/easy-rsa/
    # 初始化 PKI 并生成证书
    ./easyrsa --batch init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa --batch --days=3650 build-server-full server nopass
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass
    ./easyrsa --batch --days=3650 gen-crl
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
    chown nobody:"$group_name" /etc/openvpn/server/crl.pem
    chmod o+x /etc/openvpn/server/
    # 生成 tls-crypt 密钥
    openvpn --genkey secret /etc/openvpn/server/tc.key
    # 创建 DH 参数文件
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
    # 生成 server.conf
    echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
    if [[ -z "$ip6" ]]; then
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    else
        echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    fi
    echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
    # 配置 DNS
    case "$dns" in
        1|"")
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
            grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
                echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
            done
        ;;
        2)
            echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
        ;;
        3)
            echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
        ;;
        4)
            echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
        ;;
        5)
            echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
        ;;
        6)
            echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
        ;;
    esac
    echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
    echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
    if [[ "$protocol" = "udp" ]]; then
        echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
    fi
    # 启用 IP 转发
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "$ip6" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
    # 配置防火墙
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/"$protocol"
        firewall-cmd --zone=trusted --add-source=10.8.0.0/24
        firewall-cmd --permanent --add-port="$port"/"$protocol"
        firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
        if [[ -n "$ip6" ]]; then
            firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
        fi
    else
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
        if [[ -n "$ip6" ]]; then
            echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
        fi
        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
        systemctl enable --now openvpn-iptables.service
    fi
    # 如果 SELinux 启用且端口非默认，调整端口权限
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
        if ! hash semanage 2>/dev/null; then
            dnf install -y policycoreutils-python-utils
        fi
        semanage port -a -t openvpn_port_t -p "$protocol" "$port"
    fi
    # 如果服务器在 NAT 后面，使用公网 IP
    [[ -n "$public_ip" ]] && ip="$public_ip"
    # 创建客户端模板文件
    echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
    # 启用并启动 OpenVPN 服务
    systemctl enable --now openvpn-server@server.service
    # 生成客户端配置文件
    new_client
    echo
    echo "安装完成！"
    echo
    echo "客户端配置文件位于:" ~/"$client.ovpn"
    echo "可再次运行此脚本添加新客户端。"
else
    clear
    echo "OpenVPN 已安装。"
    echo
    echo "请选择一个选项："
    echo "   1) 添加新客户端"
    echo "   2) 吊销已有客户端"
    echo "   3) 删除 OpenVPN"
    echo "   4) 退出"
    read -p "选项: " option
    until [[ "$option" =~ ^[1-4]$ ]]; do
        echo "$option: 无效的选择。"
        read -p "选项: " option
    done
    case "$option" in
        1)
            echo
            echo "请输入客户端名称："
            read -p "名称: " unsanitized_client
            client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
            while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
                echo "$client: 无效的名称。"
                read -p "名称: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
            done
            cd /etc/openvpn/server/easy-rsa/
            ./easyrsa --batch --days=3650 build-client-full "$client" nopass
            new_client
            echo
            echo "$client 已添加。配置文件位于:" ~/"$client.ovpn"
            exit
        ;;
        2)
            number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
            if [[ "$number_of_clients" = 0 ]]; then
                echo
                echo "没有现有的客户端！"
                exit
            fi
            echo
            echo "请选择要吊销的客户端："
            tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
            read -p "客户端: " client_number
            until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                echo "$client_number: 无效的选择。"
                read -p "客户端: " client_number
            done
            client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
            echo
            read -p "确认吊销 $client？[y/N]: " revoke
            until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
                echo "$revoke: 无效的选择。"
                read -p "确认吊销 $client？[y/N]: " revoke
            done
            if [[ "$revoke" =~ ^[yY]$ ]]; then
                cd /etc/openvpn/server/easy-rsa/
                ./easyrsa --batch revoke "$client"
                ./easyrsa --batch --days=3650 gen-crl
                rm -f /etc/openvpn/server/crl.pem
                cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                chown nobody:"$group_name" /etc/openvpn/server/crl.pem
                echo
                echo "$client 已吊销！"
            else
                echo
                echo "$client 吊销已中止！"
            fi
            exit
        ;;
        3)
            echo
            read -p "确认删除 OpenVPN？[y/N]: " remove
            until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                echo "$remove: 无效的选择。"
                read -p "确认删除 OpenVPN？[y/N]: " remove
            done
            if [[ "$remove" =~ ^[yY]$ ]]; then
                port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
                    firewall-cmd --remove-port="$port"/"$protocol"
                    firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
                    firewall-cmd --permanent --remove-port="$port"/"$protocol"
                    firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
                    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
                    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
                    if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
                        ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
                        firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                        firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
                        firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                        firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
                    fi
                else
                    systemctl disable --now openvpn-iptables.service
                    rm -f /etc/systemd/system/openvpn-iptables.service
                fi
                if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
                    semanage port -d -t openvpn_port_t -p "$protocol" "$port"
                fi
                systemctl disable --now openvpn-server@server.service
                rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
                rm -f /etc/sysctl.d/99-openvpn-forward.conf
                if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
                    rm -rf /etc/openvpn/server
                    apt-get remove --purge -y openvpn
                else
                    dnf remove -y openvpn
                    rm -rf /etc/openvpn/server
                fi
                echo
                echo "OpenVPN 已删除！"
            else
                echo
                echo "OpenVPN 删除已中止！"
            fi
            exit
        ;;
        4)
            exit
        ;;
    esac
fi
