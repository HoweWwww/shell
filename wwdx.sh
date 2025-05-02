#!/bin/bash

# 日志文件路径
LOG_FILE="/var/log/wwdx.log"

# 记录日志函数
log() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | sudo tee -a "$LOG_FILE" >/dev/null
}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 系统检测和初始化
# 全局缓存变量
declare -gA SYSTEM_INFO_CACHE

init_system() {
    # 如果已经初始化过则直接返回
    if [[ -n "${SYSTEM_INFO_CACHE[initialized]}" ]]; then
        return
    fi

    # 检测操作系统和硬件信息
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        SYSTEM_INFO_CACHE[os]=$ID
        SYSTEM_INFO_CACHE[os_version]=$VERSION_ID
        SYSTEM_INFO_CACHE[os_pretty_name]="$PRETTY_NAME"
    elif [ -f /etc/centos-release ]; then
        SYSTEM_INFO_CACHE[os]="centos"
        SYSTEM_INFO_CACHE[os_version]=$(grep -oE '[0-9]+\.[0-9]+' /etc/centos-release)
        SYSTEM_INFO_CACHE[os_pretty_name]=$(cat /etc/centos-release)
    elif [ -f /etc/debian_version ]; then
        SYSTEM_INFO_CACHE[os]="debian"
        SYSTEM_INFO_CACHE[os_version]=$(cat /etc/debian_version)
        SYSTEM_INFO_CACHE[os_pretty_name]="Debian ${SYSTEM_INFO_CACHE[os_version]}"
    elif [ -f /etc/alpine-release ]; then
        SYSTEM_INFO_CACHE[os]="alpine"
        SYSTEM_INFO_CACHE[os_version]=$(cat /etc/alpine-release)
        SYSTEM_INFO_CACHE[os_pretty_name]="Alpine Linux ${SYSTEM_INFO_CACHE[os_version]}"
    else
        SYSTEM_INFO_CACHE[os]=$(uname -s | tr '[:upper:]' '[:lower:]')
        SYSTEM_INFO_CACHE[os_version]=$(uname -r)
        SYSTEM_INFO_CACHE[os_pretty_name]="${SYSTEM_INFO_CACHE[os]} ${SYSTEM_INFO_CACHE[os_version]}"
    fi
    
    # 检测硬件型号
    if [ -f /sys/devices/virtual/dmi/id/product_name ]; then
        SYSTEM_INFO_CACHE[hw_model]=$(cat /sys/devices/virtual/dmi/id/product_name)
    elif command -v dmidecode &>/dev/null; then
        SYSTEM_INFO_CACHE[hw_model]=$(sudo dmidecode -s system-product-name)
    else
        SYSTEM_INFO_CACHE[hw_model]="Unknown"
    fi
    
    # 检测内核详细信息
    SYSTEM_INFO_CACHE[kernel_info]=$(uname -a)

    # 检测包管理器
    declare -A pkg_managers=(
        ["apt"]="apt"
        ["dnf"]="dnf" 
        ["yum"]="yum"
        ["pacman"]="pacman"
        ["zypper"]="zypper"
        ["apk"]="apk"
        ["emerge"]="emerge"  # Gentoo
        ["pkg"]="pkg"        # FreeBSD
        ["pkgin"]="pkgin"    # NetBSD
    )

    PKG_MANAGER="unknown"
    for cmd in "${!pkg_managers[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            PKG_MANAGER="${pkg_managers[$cmd]}"
            break
        fi
    done

    # 检测服务管理器
    declare -A service_managers=(
        ["systemctl"]="systemctl"
        ["service"]="service"
        ["rc-service"]="openrc"
        ["sv"]="runit"      # Void Linux
        ["initctl"]="upstart" # Older Ubuntu
    )

    SERVICE_MANAGER="unknown"
    for cmd in "${!service_managers[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            SERVICE_MANAGER="${service_managers[$cmd]}"
            break
        fi
    done

    # 特殊发行版处理
    if [ -f /etc/alpine-release ]; then
        # Alpine Linux特殊处理
        OS="alpine"
        [ -z "$PKG_MANAGER" ] && PKG_MANAGER="apk"
        [ -z "$SERVICE_MANAGER" ] && SERVICE_MANAGER="openrc"
    elif [ -f /etc/arch-release ]; then
        # Arch Linux特殊处理
        OS="arch"
        [ -z "$PKG_MANAGER" ] && PKG_MANAGER="pacman"
    elif [ -f /etc/gentoo-release ]; then
        # Gentoo特殊处理
        OS="gentoo"
        [ -z "$PKG_MANAGER" ] && PKG_MANAGER="emerge"
    fi

    # 检测网络配置方式
    if [ -d /etc/netplan ]; then
        NETWORK_SERVICE="netplan"
    elif [ -d /etc/sysconfig/network-scripts ]; then
        NETWORK_SERVICE="network-scripts"
    elif command -v nmcli &>/dev/null; then
        NETWORK_SERVICE="NetworkManager"
    elif [ -f /etc/network/interfaces ]; then
        NETWORK_SERVICE="interfaces"
    elif [ -d /etc/network/interfaces.d ]; then
        NETWORK_SERVICE="interfaces.d"
    elif command -v ifup &>/dev/null && command -v ifdown &>/dev/null; then
        NETWORK_SERVICE="ifupdown"
    else
        NETWORK_SERVICE="unknown"
    fi

    # 检测防火墙工具
    if command -v ufw &>/dev/null && sudo ufw status | grep -q active; then
        FIREWALL_TOOL="ufw"
    elif command -v firewall-cmd &>/dev/null && sudo firewall-cmd --state 2>&1 | grep -q running; then
        FIREWALL_TOOL="firewalld"
    elif command -v iptables &>/dev/null && sudo iptables -L -n | grep -v "Chain" | grep -v "target" | grep -q ACCEPT; then
        FIREWALL_TOOL="iptables"
    elif command -v nft &>/dev/null && sudo nft list ruleset 2>/dev/null | grep -q accept; then
        FIREWALL_TOOL="nftables"
    elif command -v iptables &>/dev/null; then
        FIREWALL_TOOL="iptables"
    else
        FIREWALL_TOOL="unknown"
    fi

    log "INFO" "系统检测: $OS_PRETTY_NAME"
    log "INFO" "硬件型号: $HW_MODEL"
    log "INFO" "内核信息: $KERNEL_INFO"
    log "INFO" "包管理器: $PKG_MANAGER"
    log "INFO" "服务管理: $SERVICE_MANAGER" 
    log "INFO" "网络配置: $NETWORK_SERVICE"
    log "INFO" "防火墙工具: $FIREWALL_TOOL"
}

# 获取当前 SSH 端口
get_current_ssh_port() {
    local port
    port=$(grep -v '^#' /etc/ssh/sshd_config | grep -oP '^Port \K\d+' | head -n1)
    log "INFO" "获取当前SSH端口: ${port:-22}"
    echo "${port:-22}"
}

# 功能1: 修改 SSH 端口
modify_ssh_port() {
    local current_port new_port
    current_port=$(get_current_ssh_port)
    echo -e "${YELLOW}当前 SSH 端口: ${current_port}${NC}"
    log "INFO" "当前SSH端口: $current_port"
    
    while true; do
        read -p "请输入新端口 (22-65535): " new_port
        if [[ ! $new_port =~ ^[0-9]+$ ]] || ((new_port < 22 || new_port > 65535)); then
            echo -e "${RED}错误: 端口号必须为 22-65535 的整数！${NC}"
            log "ERROR" "无效的端口号输入: $new_port"
            continue
        fi
        break
    done

    # 备份配置文件
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    log "INFO" "已备份SSH配置文件到 /etc/ssh/sshd_config.bak"
    
    # 替换 Port 行
    sudo sed -i -E "/^#?Port /cPort $new_port" /etc/ssh/sshd_config
    log "INFO" "已将SSH端口修改为 $new_port"
    
    # 重启 SSH 服务
    if sudo $SERVICE_MANAGER restart sshd; then
        echo -e "${GREEN}SSH 端口已修改为 $new_port，重启服务完成。${NC}"
        log "INFO" "成功重启SSH服务"
    else
        echo -e "${RED}错误: 重启SSH服务失败！${NC}"
        log "ERROR" "重启SSH服务失败"
        return 1
    fi

    # 提示防火墙放行新端口
    read -p "是否需要在防火墙中放行新端口 $new_port？(y/n) " choice
    if [[ $choice =~ ^[Yy]$ ]]; then
        allow_firewall_port "$new_port"
    fi
}

# 功能2: iptables通用管理
iptables_all() {
    echo -e "${YELLOW}====== iptables 规则管理 ======${NC}"
    echo "1. 放行端口"
    echo "2. 删除放行规则"
    echo "3. 清空所有规则"
    echo "4. 保存当前规则"
    echo "5. 恢复默认规则"
    echo "0. 返回"
    read -p "请选择操作 [0-5]: " choice
    
    case $choice in
        1)
            read -p "请输入要放行的端口(如: 80或80,443): " port
            if [[ ! $port =~ ^[0-9,]+$ ]]; then
                echo -e "${RED}错误: 端口号格式不正确${NC}"
                return 1
            fi
            sudo iptables -A INPUT -p tcp --match multiport --dports $port -j ACCEPT
            echo -e "${GREEN}已放行端口: $port${NC}"
            ;;
        2)
            sudo iptables -L INPUT --line-numbers
            read -p "请输入要删除的规则行号: " line
            sudo iptables -D INPUT $line
            echo -e "${GREEN}已删除规则${NC}"
            ;;
        3)
            read -p "确认要清空所有iptables规则吗? (y/n) " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                sudo iptables -F
                sudo iptables -X
                sudo iptables -Z
                echo -e "${GREEN}已清空所有iptables规则${NC}"
            fi
            ;;
        4)
            if command -v iptables-save &>/dev/null; then
                sudo iptables-save > /etc/iptables.rules
                echo -e "${GREEN}已保存规则到/etc/iptables.rules${NC}"
            else
                echo -e "${RED}iptables-save命令不存在${NC}"
            fi
            ;;
        5)
            read -p "确认要恢复默认iptables规则吗? (y/n) " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                sudo iptables -P INPUT ACCEPT
                sudo iptables -P FORWARD ACCEPT
                sudo iptables -P OUTPUT ACCEPT
                sudo iptables -F
                echo -e "${GREEN}已恢复默认规则${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择!${NC}"
            ;;
    esac
}

# 功能3: 防火墙放行指定端口或所有端口
allow_firewall_port() {
    local port=$1
    if [[ -z $port ]]; then
    echo "1. 放行指定端口"
    echo "2. 放行所有端口(1-65535)"
    echo "3. 关闭指定端口"
    read -p "请选择操作 [1-3]: " choice
    
    case $choice in
        1)
            while true; do
                read -p "请输入需要放行的端口号: " port
                if [[ ! $port =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
                    echo -e "${RED}错误: 端口号必须为 1-65535 的整数！${NC}"
                    log "ERROR" "无效的防火墙端口输入: $port"
                    continue
                fi
                break
            done
            ;;
        2)
            port="1-65535"
            ;;
        3)
            while true; do
                read -p "请输入需要关闭的端口号: " port
                if [[ ! $port =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
                    echo -e "${RED}错误: 端口号必须为 1-65535 的整数！${NC}"
                    log "ERROR" "无效的防火墙端口输入: $port"
                    continue
                fi
                break
            done
            close_port "$port"
            return
            ;;
            *)
                echo -e "${RED}无效选择！${NC}"
                return 1
                ;;
        esac
    fi

    case $FIREWALL_TOOL in
        ufw)
            echo -e "${YELLOW}使用 ufw 防火墙${NC}"
            if [[ $port == "1-65535" ]]; then
                sudo ufw allow 1:65535/tcp
                echo -e "${GREEN}已放行所有TCP端口 (1-65535) (ufw)${NC}"
            else
                sudo ufw allow "$port/tcp"
                echo -e "${GREEN}已放行端口 $port (ufw)${NC}"
            fi
            ;;
        firewalld)
            echo -e "${YELLOW}使用 firewalld 防火墙${NC}"
            if [[ $port == "1-65535" ]]; then
                sudo firewall-cmd --permanent --add-port=1-65535/tcp
                sudo firewall-cmd --reload
                echo -e "${GREEN}已放行所有TCP端口 (1-65535) (firewalld)${NC}"
            else
                sudo firewall-cmd --permanent --add-port="$port/tcp"
                sudo firewall-cmd --reload
                echo -e "${GREEN}已放行端口 $port (firewalld)${NC}"
            fi
            ;;
        iptables)
            echo -e "${YELLOW}使用 iptables 防火墙${NC}"
            if [[ $port == "1-65535" ]]; then
                sudo iptables -A INPUT -p tcp -m multiport --dports 1:65535 -j ACCEPT
                echo -e "${GREEN}已临时放行所有TCP端口 (1-65535) (iptables)${NC}"
            else
                sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
                echo -e "${GREEN}已临时放行端口 $port (iptables)${NC}"
            fi
            echo -e "${YELLOW}注意: iptables规则需要手动持久化${NC}"
            ;;
        nftables)
            echo -e "${YELLOW}使用 nftables 防火墙${NC}"
            if [[ $port == "1-65535" ]]; then
                sudo nft add rule inet filter input tcp dport 1-65535 accept
                echo -e "${GREEN}已临时放行所有TCP端口 (1-65535) (nftables)${NC}"
            else
                sudo nft add rule inet filter input tcp dport $port accept
                echo -e "${GREEN}已临时放行端口 $port (nftables)${NC}"
            fi
            echo -e "${YELLOW}注意: nftables规则需要手动持久化${NC}"
            ;;
        *)
            echo -e "${RED}未找到支持的防火墙工具！${NC}"
            echo -e "${YELLOW}请先安装以下任一防火墙工具:${NC}"
            case $PKG_MANAGER in
                apt)
                    echo -e "1. ufw (sudo apt install ufw)"
                    echo -e "2. firewalld (sudo apt install firewalld)"
                    echo -e "3. nftables (sudo apt install nftables)"
                    ;;
                yum|dnf)
                    echo -e "1. firewalld (sudo $PKG_MANAGER install firewalld)"
                    echo -e "2. nftables (sudo $PKG_MANAGER install nftables)"
                    ;;
                pacman)
                    echo -e "1. ufw (sudo pacman -S ufw)"
                    echo -e "2. firewalld (sudo pacman -S firewalld)"
                    echo -e "3. nftables (sudo pacman -S nftables)"
                    ;;
                zypper)
                    echo -e "1. firewalld (sudo zypper install firewalld)"
                    echo -e "2. nftables (sudo zypper install nftables)"
                    ;;
                apk)
                    echo -e "1. iptables (通常已预装)"
                    echo -e "2. nftables (sudo apk add nftables)"
                    ;;
                *)
                    echo -e "1. ufw/firewalld/iptables/nftables"
                    ;;
            esac
            echo -e "${YELLOW}或手动配置防火墙放行端口 $port${NC}"
            return 1
            ;;
    esac
}

# 功能4: 开启/关闭防火墙
toggle_firewall() {
    case $FIREWALL_TOOL in
        ufw)
            local ufw_status=$(sudo ufw status | grep -w active)
            if [[ $ufw_status == *"active"* ]]; then
                echo -e "${YELLOW}ufw 防火墙当前状态: ${GREEN}已开启${NC}"
                log "INFO" "检测到ufw防火墙已开启"
            else
                echo -e "${YELLOW}ufw 防火墙当前状态: ${RED}未开启${NC}"
                log "INFO" "检测到ufw防火墙未开启"
            fi
            echo "1. 启用防火墙"
            echo "2. 禁用防火墙"
            read -p "请选择操作 [1-2]: " choice
            case $choice in
                1) 
                    action="enable"
                    echo "y" | sudo ufw "$action" >/dev/null 2>&1
                    ;;
                2) 
                    action="disable"
                    sudo ufw "$action" >/dev/null 2>&1
                    ;;
                *) echo -e "${RED}无效选择！${NC}"; return 1 ;;
            esac
            ;;
        firewalld)
            local firewalld_status=$(sudo firewall-cmd --state 2>&1)
            if [[ $firewalld_status == *"running"* ]]; then
                echo -e "${YELLOW}firewalld 防火墙当前状态: ${GREEN}已开启${NC}"
                log "INFO" "检测到firewalld防火墙已开启"
            else
                echo -e "${YELLOW}firewalld 防火墙当前状态: ${RED}未开启${NC}"
                log "INFO" "检测到firewalld防火墙未开启"
            fi
            echo "1. 启动防火墙"
            echo "2. 停止防火墙" 
            read -p "请选择操作 [1-2]: " choice
            case $choice in
                1) action="start" ;;
                2) action="stop" ;;
                *) echo -e "${RED}无效选择！${NC}"; return 1 ;;
            esac
            sudo systemctl "$action" firewalld
            ;;
        iptables)
            echo -e "${YELLOW}iptables 防火墙当前状态:${NC}"
            sudo iptables -L -n | grep -v "Chain" | grep -v "target" | grep -q ACCEPT && \
                echo -e "${GREEN}有自定义规则${NC}" || \
                echo -e "${RED}基本规则或无规则${NC}"
            
            echo "1. 查看当前规则"
            echo "2. 管理iptables规则"
            echo "3. 保存当前规则"
            echo "4. 恢复默认规则"
            read -p "请选择操作 [1-4]: " ipt_choice
            case $ipt_choice in
                1) 
                    sudo iptables -L -n -v 
                    ;;
                2) 
                    iptables_all 
                    ;;
                3)
                    if command -v iptables-save &>/dev/null; then
                        sudo iptables-save > /etc/iptables.rules
                        echo -e "${GREEN}已保存规则到/etc/iptables.rules${NC}"
                    else
                        echo -e "${RED}iptables-save命令不存在${NC}"
                    fi
                    ;;
                4)
                    read -p "确认要恢复默认iptables规则吗? (y/n) " confirm
                    if [[ $confirm =~ ^[Yy]$ ]]; then
                        sudo iptables -P INPUT ACCEPT
                        sudo iptables -P FORWARD ACCEPT
                        sudo iptables -P OUTPUT ACCEPT
                        sudo iptables -F
                        echo -e "${GREEN}已恢复默认规则${NC}"
                    fi
                    ;;
                *) 
                    echo -e "${RED}无效选择!${NC}" 
                    ;;
            esac
            return
            ;;
        *)
            echo -e "${RED}不支持自动管理此防火墙工具 ($FIREWALL_TOOL)！${NC}"
            log "WARNING" "不支持的防火墙工具: $FIREWALL_TOOL"
            return 1
            ;;
    esac
    echo -e "${GREEN}操作完成！${NC}"
}

# ====== 网络相关功能 ======

# 功能4: 网卡状态检测
check_nic() {
    echo -e "${YELLOW}====== 网卡状态检测 ======${NC}"
    echo "1. 查看所有网卡状态"
    echo "2. 检测网络连通性"
    echo "3. 自动修复网络问题"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice

    case $choice in
        1)
            echo -e "${YELLOW}=== 网卡状态信息 ===${NC}"
            
            # 获取网卡信息
            ip -o link show | while read -r line; do
                nic=$(echo "$line" | awk -F': ' '{print $2}')
                state=$(echo "$line" | awk '{print $9}')
                mac=$(ip link show "$nic" | awk '/link\/ether/ {print $2}')
                ips=$(ip -o addr show "$nic" | awk '{print $4}' | grep -v '^inet6' | tr '\n' ' ')
                
                if [ "$state" = "UP" ]; then
                    echo -e "${GREEN}网卡: $nic 状态: UP${NC}"
                else
                    echo -e "${RED}网卡: $nic 状态: DOWN${NC}"
                fi
                echo -e "MAC地址: ${mac:-无}"
                echo -e "IP地址: ${ips:-无IP}"
                echo "----------------------------------------"
            done
            ;;
        2)
            echo -e "${YELLOW}=== 网络连通性测试 ===${NC}"
            ping -c 3 8.8.8.8 >/dev/null && \
                echo -e "${GREEN}外网连通性: 正常${NC}" || \
                echo -e "${RED}外网连通性: 异常${NC}"
            
            if grep -q "nameserver" /etc/resolv.conf; then
                local dns=$(grep "nameserver" /etc/resolv.conf | head -n1 | awk '{print $2}')
                ping -c 3 $dns >/dev/null && \
                    echo -e "${GREEN}DNS服务器($dns): 可达${NC}" || \
                    echo -e "${RED}DNS服务器($dns): 不可达${NC}"
            else
                echo -e "${RED}未配置DNS服务器${NC}"
            fi
            ;;
        3)
            echo -e "${YELLOW}=== 尝试自动修复 ===${NC}"
            # 重启网络服务
            sudo $SERVICE_MANAGER restart network >/dev/null 2>&1 || \
            sudo $SERVICE_MANAGER restart networking >/dev/null 2>&1 || \
            sudo $SERVICE_MANAGER restart NetworkManager >/dev/null 2>&1
            
            # 刷新DHCP
            sudo dhclient -r >/dev/null 2>&1
            sudo dhclient >/dev/null 2>&1
            
            echo -e "${GREEN}已尝试基本网络修复，请重新检测${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# 功能6.2：删除现有IP
delete_ip() {
    # 获取并列出网卡和IP信息(仅显示IPv4)
    echo -e "${YELLOW}当前网卡和IPv4信息:${NC}"
    ip -o addr show | awk '/inet / && !/inet6/ {print $2": "$4}' | grep -v "lo:" | while read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
    
    # 选择网卡
    echo -e "${YELLOW}可用网卡列表:${NC}"
    local i=1
    declare -A nic_map
    while read -r line; do
        nic=$(echo "$line" | awk -F': ' '{print $2}')
        nic_map[$i]=$nic
        echo "$i. $nic"
        ((i++))
    done < <(ip -o link show | grep -v "lo:")
    
    read -p "请输入要删除IP的网卡编号: " choice
    if [[ ! $choice =~ ^[0-9]+$ ]] || [[ ! ${nic_map[$choice]} ]]; then
        echo -e "${RED}错误: 无效的网卡编号！${NC}"
        return 1
    fi
    interface=${nic_map[$choice]}
    
    # 获取当前IP
    current_ip=$(ip -o addr show dev $interface | awk '/inet / && !/inet6/ {print $4}')
    if [ -z "$current_ip" ]; then
        echo -e "${RED}错误: 该网卡没有配置IP地址！${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}当前IP配置: $current_ip${NC}"
    read -p "确认要删除此IP地址吗？(y/n) " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}已取消删除操作${NC}"
        return
    fi
    
    # 删除IP
    sudo ip addr del "$current_ip" dev "$interface"
    echo -e "${GREEN}已删除IP: $current_ip${NC}"
    
    # 持久化配置
    case $NETWORK_SERVICE in
        netplan)
            echo -e "${YELLOW}使用 netplan 更新网络配置${NC}"
            local config_file="/etc/netplan/01-netcfg.yaml"
            [ -f "$config_file" ] || config_file=$(ls /etc/netplan/*.yaml | head -1)
            sudo cp "$config_file" "$config_file.bak"
            sudo sed -i "/$interface:/,/^[^ ]/ {/addresses:/!b; s|addresses: \[.*\]|addresses: []|}" "$config_file"
            sudo netplan apply
            ;;
        network-scripts)
            echo -e "${YELLOW}使用 network-scripts 更新网络配置${NC}"
            local config_file="/etc/sysconfig/network-scripts/ifcfg-$interface"
            sudo cp "$config_file" "$config_file.bak"
            sudo sed -i "/^IPADDR=/d;/^PREFIX=/d;/^NETMASK=/d" "$config_file"
            sudo systemctl restart network
            ;;
        *)
            echo -e "${YELLOW}无法自动持久化配置，请手动更新网络配置${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}IP地址删除完成！${NC}"
    log "INFO" "已删除网卡 $interface 的IP $current_ip"
}

# 功能6：IP地址管理
ip_management() {
    echo -e "${YELLOW}====== IP地址管理 ======${NC}"
    echo "1. 添加静态IP"
    echo "2. 修改现有IP"
    echo "3. 删除现有IP"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice
    
    case $choice in
        1) add_ip ;;
        2) modify_ip ;;
        3) delete_ip ;;
        0) return ;;
        *) echo -e "${RED}无效选择！${NC}" ;;
    esac
}

# 功能6.1：修改现有IP
modify_ip() {
    # 获取并列出网卡和IP信息(仅显示IPv4)
    echo -e "${YELLOW}当前网卡和IPv4信息:${NC}"
    ip -o addr show | awk '/inet / && !/inet6/ {print $2": "$4}' | grep -v "lo:" | while read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
    
    # 选择网卡
    echo -e "${YELLOW}可用网卡列表:${NC}"
    local i=1
    declare -A nic_map
    while read -r line; do
        nic=$(echo "$line" | awk -F': ' '{print $2}')
        nic_map[$i]=$nic
        echo "$i. $nic"
        ((i++))
    done < <(ip -o link show | grep -v "lo:")
    
    read -p "请输入要修改的网卡编号: " choice
    if [[ ! $choice =~ ^[0-9]+$ ]] || [[ ! ${nic_map[$choice]} ]]; then
        echo -e "${RED}错误: 无效的网卡编号！${NC}"
        return 1
    fi
    interface=${nic_map[$choice]}
    
    # 获取当前IP
    current_ip=$(ip -o addr show dev $interface | awk '/inet / {print $4}')
    echo -e "${YELLOW}当前IP配置: ${current_ip:-无}${NC}"
    
    # IP地址输入选项
    echo "1. 使用CIDR格式输入 (如 192.168.1.100/24)"
    echo "2. 分别输入IP和子网掩码"
    read -p "请选择输入方式 [1-2]: " ip_choice
    
    case $ip_choice in
        1)
            read -p "请输入新IP地址 (CIDR格式 如192.168.1.100/24): " ip_addr
            if ! [[ $ip_addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                echo -e "${RED}错误: IP地址格式不正确，请使用 CIDR 格式 (如 192.168.1.100/24)${NC}"
                return 1
            fi
            ;;
        2)
            read -p "请输入新IP地址 (如192.168.1.100): " ip
            read -p "请输入子网掩码 (如255.255.255.0): " mask
            
            # 验证IP格式
            if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED}错误: IP地址格式不正确${NC}"
                return 1
            fi
            
            # 验证子网掩码并转换为CIDR
            if ! [[ $mask =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED}错误: 无效的子网掩码格式${NC}"
                return 1
            fi
            
            # 将掩码转换为二进制计算1的个数
            cidr=0
            for octet in ${mask//./ }; do
                if [ $octet -gt 255 ]; then
                    echo -e "${RED}错误: 无效的子网掩码值${NC}"
                    return 1
                fi
                # 计算每个八位组的1的个数
                binary=$(echo "obase=2;$octet" | bc)
                cidr=$((cidr + ${binary//0/}))
            done
            
            # ${YELLOW}验证掩码有效性(连续的1)${NC}
            valid_mask=$(( (0xffffffff << (32 - cidr)) & 0xffffffff ))
            input_mask=$(echo $mask | awk -F. '{printf "0x%02x%02x%02x%02x\n", $1, $2, $3, $4}')
            if [ $((valid_mask)) -ne $((input_mask)) ]; then
                echo -e "${RED}错误: 无效的子网掩码(非连续1)${NC}"
                return 1
            fi
            ip_addr="$ip/$cidr"
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 删除旧IP
    if [ -n "$current_ip" ]; then
        sudo ip addr del "$current_ip" dev "$interface"
        echo -e "${YELLOW}已删除旧IP: $current_ip${NC}"
    fi
    
    # 添加新IP
    sudo ip addr add "$ip_addr" dev "$interface"
    echo -e "${GREEN}已添加新IP: $ip_addr${NC}"
    
    # 持久化配置
    case $NETWORK_SERVICE in
        netplan)
            echo -e "${YELLOW}使用 netplan 更新网络配置${NC}"
            local config_file="/etc/netplan/01-netcfg.yaml"
            [ -f "$config_file" ] || config_file=$(ls /etc/netplan/*.yaml | head -1)
            sudo cp "$config_file" "$config_file.bak"
            sudo sed -i "/$interface:/,/^[^ ]/ {/addresses:/!b; s|addresses: \[.*\]|addresses: [$ip_addr]|}" "$config_file"
            sudo netplan apply
            ;;
        network-scripts)
            echo -e "${YELLOW}使用 network-scripts 更新网络配置${NC}"
            local config_file="/etc/sysconfig/network-scripts/ifcfg-$interface"
            sudo cp "$config_file" "$config_file.bak"
            sudo sed -i "/^IPADDR=/d;/^PREFIX=/d;/^NETMASK=/d" "$config_file"
            echo "IPADDR=${ip_addr%/*}" | sudo tee -a "$config_file"
            echo "PREFIX=${ip_addr#*/}" | sudo tee -a "$config_file"
            sudo systemctl restart network
            ;;
        *)
            echo -e "${YELLOW}无法自动持久化配置，请手动更新网络配置${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}IP地址修改完成！${NC}"
    log "INFO" "已修改网卡 $interface 的IP为 $ip_addr"
}

# 功能5：网卡
add_ip() {
    # 获取并列出网卡列表
    echo -e "${YELLOW}可用网卡列表:${NC}"
    local i=1
    declare -A nic_map
    while read -r line; do
        nic=$(echo "$line" | awk -F': ' '{print $2}')
        nic_map[$i]=$nic
        echo "$i. $nic"
        ((i++))
    done < <(ip -o link show)
    
    # 选择网卡
    read -p "请输入要配置的网卡编号: " choice
    if [[ ! $choice =~ ^[0-9]+$ ]] || [[ ! ${nic_map[$choice]} ]]; then
        echo -e "${RED}错误: 无效的网卡编号！${NC}"
        return 1
    fi
    interface=${nic_map[$choice]}
    
    # IP地址输入选项
    echo "1. 使用CIDR格式输入 (如 192.168.1.100/24)"
    echo "2. 分别输入IP和子网掩码"
    read -p "请选择输入方式 [1-2]: " ip_choice
    
    case $ip_choice in
        1)
            read -p "请输入IP地址 (CIDR格式 如192.168.1.100/24): " ip_addr
            if ! [[ $ip_addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                echo -e "${RED}错误: IP地址格式不正确，请使用 CIDR 格式 (如 192.168.1.100/24)${NC}"
                return 1
            fi
            ;;
        2)
            read -p "请输入IP地址 (如192.168.1.100): " ip
            read -p "请输入子网掩码 (如255.255.255.0): " mask
            
            # 验证IP格式
            if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED}错误: IP地址格式不正确${NC}"
                return 1
            fi
            
            # 将掩码转换为二进制计算1的个数
            cidr=0
            for octet in ${mask//./ }; do
                if [ $octet -gt 255 ]; then
                    echo -e "${RED}错误: 无效的子网掩码值${NC}"
                    return 1
                fi
                # 计算每个八位组的1的个数
                binary=$(echo "obase=2;$octet" | bc)
                cidr=$((cidr + ${binary//0/}))
            done

            # 验证掩码有效性(连续的1)
            valid_mask=$(( (0xffffffff << (32 - cidr)) & 0xffffffff ))
            input_mask=$(echo $mask | awk -F. '{printf "0x%02x%02x%02x%02x\n", $1, $2, $3, $4}')
            if [ $((valid_mask)) -ne $((input_mask)) ]; then
                echo -e "${RED}错误: 无效的子网掩码(非连续1)${NC}"
                return 1
            fi
            ip_addr="$ip/$cidr"
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac
    
    # 临时添加IP
    sudo ip addr add "$ip_addr" dev "$interface"
    echo -e "${GREEN}已临时添加IP $ip_addr 到 $interface${NC}"
    
    # 持久化配置
    case $NETWORK_SERVICE in
        netplan)
            echo -e "${YELLOW}使用 netplan 配置网络${NC}"
            local config_file="/etc/netplan/01-netcfg.yaml"
            [ -f "$config_file" ] || config_file=$(ls /etc/netplan/*.yaml | head -1)
            sudo cp "$config_file" "$config_file.bak"
            sudo sed -i "/$interface:/,/^[^ ]/ {/addresses:/!b; s|addresses: \[.*\]|addresses: [$(ip -4 addr show $interface | grep -oP 'inet \K[\d./]+'), $ip_addr]|}" "$config_file"
            sudo netplan apply
            ;;
        network-scripts)
            echo -e "${YELLOW}使用 network-scripts 配置网络${NC}"
            local config_file="/etc/sysconfig/network-scripts/ifcfg-$interface"
            sudo cp "$config_file" "$config_file.bak"
            if grep -q "IPADDR2" "$config_file"; then
                local next_num=$(grep -o 'IPADDR[0-9]\+' "$config_file" | tail -1 | tr -d 'IPADDR')
                next_num=$((next_num + 1))
                echo "IPADDR$next_num=${ip_addr%/*}" | sudo tee -a "$config_file"
                echo "PREFIX$next_num=${ip_addr#*/}" | sudo tee -a "$config_file"
            else
                echo "IPADDR2=${ip_addr%/*}" | sudo tee -a "$config_file"
                echo "PREFIX2=${ip_addr#*/}" | sudo tee -a "$config_file"
            fi
            sudo systemctl restart network
            ;;
        *)
            echo -e "${YELLOW}无法自动持久化配置，请手动添加IP到系统网络配置${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}已持久化添加IP $ip_addr 到 $interface${NC}"
}

# ====== 系统信息功能 ======

# 功能7: 显示系统信息
show_system_info() {
    # 确保系统信息已初始化
    init_system
    
    echo -e "${YELLOW}====== 系统信息 ======${NC}"
    echo -e "主机名: $(hostname)"
    echo -e "操作系统: ${SYSTEM_INFO_CACHE[os_pretty_name]}"
    echo -e "硬件型号: ${SYSTEM_INFO_CACHE[hw_model]}"
    echo -e "内核版本: $(uname -r)"
    echo -e "CPU信息: $(grep 'model name' /proc/cpuinfo | head -n1 | cut -d':' -f2 | sed 's/^[ \t]*//')"
    echo -e "CPU核心数: $(nproc)"
    echo -e "内存总量: $(free -h | grep Mem | awk '{print $2}')"
    echo -e "内存使用: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo -e "磁盘空间: $(df -h / | awk 'NR==2 {print $3"/"$2 " ("$5")"}')"
    echo -e "IP地址: $(hostname -I | awk '{print $1}')"
    echo -e "SSH端口: $(get_current_ssh_port)"
    echo -e "系统运行时间: $(uptime -p)"
    echo -e "${YELLOW}=====================${NC}"
    log "INFO" "查看系统信息"
}

# ====== 账户管理功能 ======

# 功能7: 用户管理
user_management() {
    echo -e "${YELLOW}====== 用户管理 ======${NC}"
    echo "1. 添加用户"
    echo "2. 修改密码"
    echo "3. 删除用户"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice
    
    case $choice in
        1)
            read -p "请输入用户名: " username
            sudo useradd -m "$username"
            sudo passwd "$username"
            echo -e "${GREEN}用户 $username 添加成功${NC}"
            ;;
        2)
            read -p "请输入用户名: " username
            sudo passwd "$username"
            ;;
        3)
            read -p "请输入要删除的用户名: " username
            sudo userdel -r "$username"
            echo -e "${GREEN}用户 $username 已删除${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# ====== 系统维护功能 ======

# 功能8: 服务管理
service_management() {
    echo -e "${YELLOW}====== 服务管理 ======${NC}"
    echo "1. 列出所有服务"
    echo "2. 启动服务"
    echo "3. 停止服务"
    echo "4. 重启服务"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-4]: " choice
    
    case $choice in
        1)
            sudo $SERVICE_MANAGER list-unit-files --type=service
            ;;
        2)
            read -p "请输入服务名: " service
            sudo $SERVICE_MANAGER start "$service"
            ;;
        3)
            read -p "请输入服务名: " service
            sudo $SERVICE_MANAGER stop "$service"
            ;;
        4)
            read -p "请输入服务名: " service
            sudo $SERVICE_MANAGER restart "$service"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# 功能9: 磁盘清理
disk_cleanup() {
    echo -e "${YELLOW}====== 磁盘清理 ======${NC}"
    echo "1. 清理临时文件"
    echo "2. 清理旧内核"
    echo "3. 清理日志文件"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice
    
    case $choice in
        1)
            sudo apt-get clean || sudo yum clean all
            echo -e "${GREEN}临时文件已清理${NC}"
            ;;
        2)
            sudo apt-get autoremove --purge || sudo package-cleanup --oldkernels --count=1
            echo -e "${GREEN}旧内核已清理${NC}"
            ;;
        3)
            sudo journalctl --vacuum-time=7d
            echo -e "${GREEN}日志文件已清理${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# ====== 软件管理功能 ======

# 功能10: 更换软件源
change_repo_source() {
    echo -e "${YELLOW}====== 更换软件源 ======${NC}"
    echo "1. 默认官方源"
    echo "2. 阿里云源"
    echo "3. 腾讯云源" 
    echo "4. 华为云源"
    echo "5. 清华大学源"
    echo "0. 返回主菜单"
    read -p "请选择源 [0-5]: " choice

    # 备份当前源
    backup_repo() {
        case $PKG_MANAGER in
            apt)
                sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
                ;;
            yum|dnf)
                sudo mkdir -p /etc/yum.repos.d/backup
                sudo mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup/
                ;;
            pacman)
                sudo cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.bak
                ;;
        esac
        echo -e "${GREEN}已备份当前软件源配置${NC}"
    }

    # 设置新源
    case $choice in
        1) # 默认源
            backup_repo
            case $PKG_MANAGER in
                apt)
                    sudo sed -i 's|https\?://[^/]\+/|http://archive.ubuntu.com/|g' /etc/apt/sources.list
                    ;;
                yum|dnf)
                    sudo cp /etc/yum.repos.d/backup/*.repo /etc/yum.repos.d/
                    ;;
                pacman)
                    sudo sed -i 's|^Server = .*|# &|g' /etc/pacman.d/mirrorlist
                    echo 'Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch' | sudo tee -a /etc/pacman.d/mirrorlist
                    ;;
            esac
            echo -e "${GREEN}已切换为默认官方源${NC}"
            ;;
        2) # 阿里云
            backup_repo
            case $PKG_MANAGER in
                apt)
                    sudo sed -i 's|https\?://[^/]\+/|https://mirrors.aliyun.com/|g' /etc/apt/sources.list
                    ;;
                yum|dnf)
                    if [[ $OS_VERSION == "9" ]]; then
                        echo -e "${YELLOW}正在下载CentOS 9 Stream阿里云源配置...${NC}"
                        if ! sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Stream-Base.repo https://mirrors.aliyun.com/repo/Centos-vault-9.0.repo; then
                            echo -e "${RED}下载阿里云源配置失败，尝试使用备用镜像...${NC}"
                            sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Stream-Base.repo https://mirrors.aliyun.com/centos-vault/9.0.0/repo/Centos-vault-9.0.repo
                        fi
                    else
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
                    fi
                    ;;
                pacman)
                    sudo sed -i 's|^Server = .*|# &|g' /etc/pacman.d/mirrorlist
                    echo 'Server = https://mirrors.aliyun.com/archlinux/$repo/os/$arch' | sudo tee -a /etc/pacman.d/mirrorlist
                    ;;
            esac
            echo -e "${GREEN}已切换为阿里云源${NC}"
            ;;
        3) # 腾讯云
            backup_repo
            case $PKG_MANAGER in
                apt)
                    sudo sed -i 's|https\?://[^/]\+/|https://mirrors.cloud.tencent.com/|g' /etc/apt/sources.list
                    ;;
                yum|dnf)
                    if [[ $OS_VERSION == "9" ]]; then
                        echo -e "${YELLOW}正在下载CentOS 9 Stream腾讯云源配置...${NC}"
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Stream-Base.repo https://mirrors.cloud.tencent.com/repo/centos9_base.repo
                    else
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.cloud.tencent.com/repo/centos7_base.repo
                    fi
                    ;;
                pacman)
                    sudo sed -i 's|^Server = .*|# &|g' /etc/pacman.d/mirrorlist
                    echo 'Server = https://mirrors.cloud.tencent.com/archlinux/$repo/os/$arch' | sudo tee -a /etc/pacman.d/mirrorlist
                    ;;
            esac
            echo -e "${GREEN}已切换为腾讯云源${NC}"
            ;;
        4) # 华为云
            backup_repo
            case $PKG_MANAGER in
                apt)
                    sudo sed -i 's|https\?://[^/]\+/|https://repo.huaweicloud.com/|g' /etc/apt/sources.list
                    ;;
                yum|dnf)
                    if [[ $OS_VERSION == "9" ]]; then
                        echo -e "${YELLOW}正在下载CentOS 9 Stream华为云源配置...${NC}"
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Stream-Base.repo https://repo.huaweicloud.com/repository/conf/CentOS-9-reg.repo
                    else
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Base.repo https://repo.huaweicloud.com/repository/conf/CentOS-7-reg.repo
                    fi
                    ;;
                pacman)
                    sudo sed -i 's|^Server = .*|# &|g' /etc/pacman.d/mirrorlist
                    echo 'Server = https://repo.huaweicloud.com/archlinux/$repo/os/$arch' | sudo tee -a /etc/pacman.d/mirrorlist
                    ;;
            esac
            echo -e "${GREEN}已切换为华为云源${NC}"
            ;;
        5) # 清华大学
            backup_repo
            case $PKG_MANAGER in
                apt)
                    sudo sed -i 's|https\?://[^/]\+/|https://mirrors.tuna.tsinghua.edu.cn/|g' /etc/apt/sources.list
                    ;;
                yum|dnf)
                    if [[ $OS_VERSION == "9" ]]; then
                        echo -e "${YELLOW}正在下载CentOS 9 Stream清华大学源配置...${NC}"
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Stream-Base.repo https://mirrors.tuna.tsinghua.edu.cn/repo/centos9.repo
                    else
                        sudo curl --connect-timeout 10 --retry 3 -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.tuna.tsinghua.edu.cn/repo/centos7.repo
                    fi
                    ;;
                pacman)
                    sudo sed -i 's|^Server = .*|# &|g' /etc/pacman.d/mirrorlist
                    echo 'Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/$repo/os/$arch' | sudo tee -a /etc/pacman.d/mirrorlist
                    ;;
            esac
            echo -e "${GREEN}已切换为清华大学源${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac

    # 更新软件包索引
    case $PKG_MANAGER in
        apt) sudo apt update ;;
        yum|dnf) sudo $PKG_MANAGER makecache ;;
        pacman) sudo pacman -Sy ;;
    esac
}

# ====== 安全相关功能 ======

# 功能11: 系统安全扫描
security_scan() {
    echo -e "${YELLOW}====== 系统安全扫描 ======${NC}"
    echo "1. 检查SSH安全配置"
    echo "2. 检查可疑进程"
    echo "3. 检查异常登录"
    echo "4. 检查root远程登录"
    echo "0. 返回主菜单"
    read -p "请选择扫描类型 [0-4]: " choice
    
    case $choice in
        1)
            echo -e "${YELLOW}=== SSH安全配置检查 ===${NC}"
            # 检查密码登录
            grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config && \
                echo -e "${GREEN}[安全] 已禁用密码登录${NC}" || \
                echo -e "${RED}[风险] 允许密码登录${NC}"
            
            # 检查root登录
            grep -q "^PermitRootLogin no" /etc/ssh/sshd_config && \
                echo -e "${GREEN}[安全] 已禁止root远程登录${NC}" || \
                echo -e "${RED}[风险] 允许root远程登录${NC}"
            
            # 检查空密码
            grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config && \
                echo -e "${GREEN}[安全] 已禁止空密码登录${NC}" || \
                echo -e "${RED}[风险] 允许空密码登录${NC}"
            ;;
        2)
            echo -e "${YELLOW}=== 可疑进程检查 ===${NC}"
            echo -e "高CPU使用进程:"
            ps -eo pid,user,%cpu,cmd --sort=-%cpu | head -n 5
            echo -e "\n高内存使用进程:"
            ps -eo pid,user,%mem,cmd --sort=-%mem | head -n 5
            ;;
        3)
            echo -e "${YELLOW}=== 异常登录检查 ===${NC}"
            last | head -n 10
            echo -e "\n失败登录尝试:"
            sudo grep "Failed password" /var/log/auth.log | tail -n 5
            ;;
        4)
            echo -e "${YELLOW}=== Root登录检查 ===${NC}"
            sudo grep "root" /var/log/auth.log | grep "Accepted password"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# ====== 性能相关功能 ======

# 功能12: 性能调优
performance_tuning() {
    echo -e "${YELLOW}====== 性能调优 ======${NC}"
    echo "1. 优化文件描述符限制"
    echo "2. 优化内核参数"
    echo "3. 优化SWAP使用"
    echo "0. 返回主菜单"
    read -p "请选择优化项 [0-3]: " choice
    
    case $choice in
        1)
            echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
            echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
            echo -e "${GREEN}已优化文件描述符限制为65535${NC}"
            ;;
        2)
            echo "vm.swappiness = 10" | sudo tee -a /etc/sysctl.conf
            echo "net.core.somaxconn = 4096" | sudo tee -a /etc/sysctl.conf
            sudo sysctl -p
            echo -e "${GREEN}已优化内核参数${NC}"
            ;;
        3)
            sudo sed -i '/swap/s/^/#/' /etc/fstab
            sudo swapoff -a
            echo -e "${GREEN}已禁用SWAP${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# ====== 软件安装功能 ======

# 功能14: 安装常用软件
install_common_software() {
    echo -e "${YELLOW}====== 安装常用软件 ======${NC}"
    echo "1. 安装基础工具"
    echo "2. 安装开发工具" 
    echo "3. 安装系统工具"
    echo "4. 安装全部软件"
    echo "0. 返回主菜单"
    read -p "请选择安装类型 [0-4]: " choice

    case $choice in
        1) # 基础工具
            packages="curl wget vim nano tmux htop net-tools"
            ;;
        2) # 开发工具
            packages="git gcc make cmake python3 python3-pip"
            ;;
        3) # 系统工具
            packages="iotop iftop nload ncdu"
            ;;
        4) # 全部软件
            packages="curl wget vim nano tmux htop net-tools git gcc make cmake python3 python3-pip iotop iftop nload ncdu"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            return 1
            ;;
    esac

    echo -e "${YELLOW}即将安装: ${packages}${NC}"
    read -p "确认安装? (y/n) " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        case $PKG_MANAGER in
            apt)
                sudo apt update && sudo apt install -y $packages
                ;;
            yum|dnf)
                sudo $PKG_MANAGER install -y $packages
                ;;
            pacman)
                sudo pacman -Syu --noconfirm $packages
                ;;
            zypper)
                sudo zypper refresh && sudo zypper install -y $packages
                ;;
            apk)
                sudo apk update && sudo apk add $packages
                ;;
            *)
                echo -e "${RED}不支持自动安装，请手动安装: ${packages}${NC}"
                return 1
                ;;
        esac
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}软件安装成功！${NC}"
            log "INFO" "成功安装软件: $packages"
        else
            echo -e "${RED}软件安装失败！${NC}"
            log "ERROR" "安装软件失败: $packages"
        fi
    else
        echo -e "${YELLOW}已取消安装${NC}"
    fi
}

# 功能15: 宝塔面板管理
baota_management() {
    echo -e "${YELLOW}====== 宝塔面板管理 ======${NC}"
    echo "1. 安装宝塔面板(国内版)"
    echo "2. 安装宝塔面板(海外版)"
    echo "3. 卸载宝塔面板"
    echo "0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice

    case $choice in
        1) # 国内版
            echo -e "${YELLOW}正在安装宝塔面板(国内版)...${NC}"
            curl -sSO http://download.bt.cn/install/install_panel.sh && bash install_panel.sh
            ;;
        2) # 海外版
            echo "1. 安装6.0版本（稳定版）"
            echo "2. 安装7.0版本（最新Free）" 
            read -p "请选择版本 [1-2]: " ver_choice
            
            case $ver_choice in
                1)
                    wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh && bash install.sh
                    ;;
                2)
                    URL="https://www.aapanel.com/script/install_7.0_en.sh"
                    if [ -f /usr/bin/curl ]; then
                        curl -ksSO "$URL" && bash install_7.0_en.sh aapanel
                    else
                        wget --no-check-certificate -O install_7.0_en.sh "$URL" && bash install_7.0_en.sh aapanel
                    fi
                    ;;
                *)
                    echo -e "${RED}无效选择，请重新选择[1-2]${NC}"
                    continue
                    ;;
            esac
            ;;
        3) # 卸载
            echo -e "${YELLOW}正在卸载宝塔面板...${NC}"
            wget http://download.bt.cn/install/bt-uninstall.sh && bash bt-uninstall.sh
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效选择！${NC}"
            ;;
    esac
}

# ====== 备份恢复功能 ======

# 功能13: 恢复SSH配置备份
restore_ssh_config() {
    if [[ ! -f /etc/ssh/sshd_config.bak ]]; then
        echo -e "${RED}错误: 未找到备份文件 /etc/ssh/sshd_config.bak${NC}"
        log "ERROR" "尝试恢复SSH配置但未找到备份文件"
        return 1
    fi
    
    echo -e "${YELLOW}当前SSH端口: $(get_current_ssh_port)${NC}"
    echo -e "${YELLOW}备份文件内容:${NC}"
    grep -oP '^Port \K\d+' /etc/ssh/sshd_config.bak | head -n1
    
    read -p "确认要恢复备份配置吗？(y/n) " choice
    if [[ $choice =~ ^[Yy]$ ]]; then
        sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        sudo $SERVICE_MANAGER restart sshd
        echo -e "${GREEN}已成功恢复SSH配置备份${NC}"
        log "INFO" "已恢复SSH配置备份"
    else
        echo -e "${YELLOW}已取消恢复操作${NC}"
        log "INFO" "用户取消SSH配置恢复"
    fi
}

# 主菜单
show_menu() {
    clear
    echo -e "\033[1;36m╔═════════════════════════════════════════════════╗"
    echo -e "║                 \033[1;37m系统管理脚本 \033\033[1;36m                   ║"
    echo -e "╠═════════════════════════════════════════════════╣"
    echo -e "║ \033[1;32m 1.修改SSH端口　 \033[1;32m 2.防火墙放行　 \033[1;32m 3.开关防火墙  \033[1;36m║"
    echo -e "║ \033[1;32m 4.iptables管理　\033[1;32m 5.网卡检测　　 \033[1;32m 6.IP地址管理  \033[1;36m║"
    echo -e "║ \033[1;32m 7.系统信息　　　\033[1;32m 8.用户管理　　 \033[1;32m 9.服务管理　  \033[1;36m║"
    echo -e "║ \033[1;32m10.磁盘清理　　　\033[1;32m11.更换软件源　 \033[1;32m12.安全扫描　  \033[1;36m║"
    echo -e "║ \033[1;32m13.性能调优　　　\033[1;32m14.恢复SSH配置 \033[1;32m 15.安装常用软件\033[1;36m║"
    echo -e "║ \033[1;32m16.宝塔管理　　　　　　　　　　　　　　　　　   \033[1;36m║"
    echo -e "║ \033[1;31m 0.退出脚本　　　　　　　　　　　　　　　　　　 \033[1;36m║"
    echo -e "╚═════════════════════════════════════════════════╝\033[0m"
    echo -e " \033[1;34m系统:\033[1;33m${SYSTEM_INFO_CACHE[os_pretty_name]}\033[0m  \033[1;34m     时间:\033[1;33m$(date '+%Y-%m-%d %H:%M:%S')\033[0m"
    echo -e " \033[1;34m日志:\033[1;33m$LOG_FILE\033[0m      \033[1;34mSSH端口:\033[1;33m$(get_current_ssh_port)\033[0m"
}

# 初始化系统
init_system

# 主循环
while true; do
    show_menu
    read -p "请输入选项编号: " choice
    case $choice in
        1) modify_ssh_port ;;
        2) allow_firewall_port ;;
        3) toggle_firewall ;;
        4) iptables_all;;
        5) check_nic;;
        6) ip_management;;
        7) show_system_info;;
        8) user_management;;
        9) service_management;;
        10) disk_cleanup;;
        11) change_repo_source;;
        12) security_scan;;
        13) performance_tuning;;
        14) restore_ssh_config;;
        15) install_common_software;;
        16) baota_management;;
        0) echo -e "${GREEN}已退出脚本。${NC}"; log "INFO" "脚本正常退出"; exit 0 ;;
        *) echo -e "${RED}无效选项，请重新输入！${NC}"; log "WARNING" "无效菜单选项: $choice" ;;
    esac
    read -p "按回车键继续..."
done
