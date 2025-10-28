#!/bin/bash

# Colors
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${GREEN}"
cat << "EOF"
 ██╗     ██╗███╗   ██╗██████╗ ██╗███████╗██████╗ 
 ██║     ██║████╗  ██║██╔══██╗██║╚══███╔╝██╔══██╗
 ██║     ██║██╔██╗ ██║██████╔╝██║  ███╔╝ ██████╔╝
 ██║     ██║██║╚██╗██║██╔══██╗██║ ███╔╝  ██╔══██╗
 ███████╗██║██║ ╚████║██████╔╝██║███████╗██║  ██║
 ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${MAGENTA}        Ultimate NTP Enumerator       "
echo -e "${BLUE}               by Linbizer Security        ${RESET}"
echo -e "${WHITE}------------------------------------------------${RESET}"

# Check arguments
if [ $# -ne 1 ]; then
    echo -e "${RED}Usage: $0 <IP_or_CIDR>${NC}"
    exit 1
fi

target=$1

# Function to get NTP info for a single host
get_ntp_info() {
    local ip=$1
    local result=$(nmap -sU -p 123 --script=ntp-info $ip 2>/dev/null)
    
    local stratum=$(echo "$result" | grep 'stratum:' | awk '{print $NF}')
    local refid=$(echo "$result" | grep 'refid:' | awk '{print $NF}' | tr -d '()')
    local version=$(echo "$result" | grep 'version:' | awk '{print $NF}')
    local system=$(echo "$result" | grep 'system:' | awk '{print $NF}')
    
    echo "$ip $stratum $refid $version $system"
}

# scan function
scan_network() {
    echo -e "${YELLOW}[*] Scanning $target...${NC}"
    
    # Temporary files
    hosts_file=$(mktemp)
    ntp_data_file=$(mktemp)
    
    # First find responsive hosts
    echo -e "${YELLOW}[*] Identifying live NTP hosts...${NC}"
    nmap -sU -p 123 --open $target -oG $hosts_file >/dev/null
    live_hosts=$(grep 'open' $hosts_file | awk '{print $2}')
    
    # Get NTP info for all live hosts
    echo -e "${YELLOW}[*] Gathering NTP information...${NC}"
    for ip in $live_hosts; do
        echo -ne "${BLUE}Processing $ip...${NC}\r"
        get_ntp_info $ip >> $ntp_data_file
    done
    echo -ne "\033[K" # Clear line
    
    # Process NTP data
    declare -A ntp_servers
    while read -r line; do
        read ip stratum refid version system <<< "$line"
        ntp_servers["$ip"]="$stratum $refid $version $system"
    done < $ntp_data_file
    
    # Identify true masters (either stratum 1 or using local clock)
    echo -e "\n${GREEN}NTP HIERARCHY:${NC}"
    echo -e "${PURPLE}🟣 MASTER SERVERS${NC}"
    found_master=0
    
    for ip in "${!ntp_servers[@]}"; do
        read stratum refid version system <<< "${ntp_servers[$ip]}"
        
        # Check if it's a true master (stratum 1 or using local clock)
        if [[ "$stratum" == "1" ]] || [[ "$refid" == 127.*.*.* ]] || [[ "$refid" == "LOCL" ]]; then
            echo -e "  IP: $ip"
            echo -e "  Stratum: $stratum"
            echo -e "  RefID: $refid"
            echo -e "  Version: NTP v$version"
            echo -e "  System: $system"
            
            # Check for monlist vulnerability
            if [[ "$version" == *"4.2.8"* ]]; then
                echo -e "${RED}  [!] Potential CVE-2013-5211 (monlist) vulnerability${NC}"
            fi
            echo ""
            found_master=1
            
            # Correct stratum if it's using local clock but reporting higher stratum
            if [[ "$refid" == 127.*.*.* ]] && [[ "$stratum" != "1" ]]; then
                echo -e "${YELLOW}  [!] Warning: Server using local clock but reporting stratum $stratum (should be 1)${NC}"
                echo ""
            fi
        fi
    done
    
    if [ "$found_master" -eq 0 ]; then
        echo -e "${YELLOW}  No master servers found in the scanned network${NC}"
    fi
    
    # Identify clients
    echo -e "${BLUE}🔵 CLIENT SERVERS${NC}"
    found_client=0
    
    for ip in "${!ntp_servers[@]}"; do
        read stratum refid version system <<< "${ntp_servers[$ip]}"
        
        # Skip masters we already identified
        if [[ "$stratum" == "1" ]] || [[ "$refid" == 127.*.*.* ]] || [[ "$refid" == "LOCL" ]]; then
            continue
        fi
        
        echo -e "  IP: $ip"
        echo -e "  Stratum: $stratum"
        echo -e "  Sync Source: $refid"
        echo -e "  Version: NTP v$version"
        
        # Try to find upstream server in our data
        upstream_ip=""
        for possible_upstream in "${!ntp_servers[@]}"; do
            if [[ "$refid" == "$possible_upstream" ]]; then
                upstream_ip="$possible_upstream"
                break
            fi
        done
        
        if [ -n "$upstream_ip" ]; then
            read upstream_stratum <<< "${ntp_servers[$upstream_ip]}"
            echo -e "  Upstream Server: $upstream_ip (stratum $upstream_stratum)"
        else
            echo -e "  Upstream Server: $refid (external)"
        fi
        echo ""
        found_client=1
    done
    
    if [ "$found_client" -eq 0 ]; then
        echo -e "${YELLOW}  No client servers found in the scanned network${NC}"
    fi
    
    # Identify non-responsive hosts (shortened output)
    echo -e "\n${YELLOW}⚠️  NON-RESPONSIVE HOSTS (showing first 10)${NC}"
    all_hosts=$(nmap -sL -n $target | grep 'scan report' | awk '{print $NF}')
    count=0
    for ip in $all_hosts; do
        if ! echo "$live_hosts" | grep -q "$ip"; then
            state=$(grep "$ip" $hosts_file | awk '{print $NF}')
            case "$state" in
                "closed") echo -e "${RED}  Closed: $ip${NC}" ;;
                "filtered") echo -e "${YELLOW}  Filtered: $ip${NC}" ;;
                *) echo -e "${YELLOW}  No response: $ip${NC}" ;;
            esac
            ((count++))
            [ $count -eq 10 ] && break
        fi
    done
    [ $count -eq 10 ] && echo -e "${YELLOW}  [...] (showing first 10 of many)${NC}"

    # Cleanup
    rm -f $hosts_file $ntp_data_file
}

scan_network
echo -e "\n${GREEN}[+] Scan completed at $(date)${NC}"
