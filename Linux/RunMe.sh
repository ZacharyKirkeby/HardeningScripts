#!/bin/bash

# Automated Hardening Script for Linux
# Each Section is labeled. Review changes before using this script.

if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root."
    exit 1
fi

echo "Starting Linux Hardening Script..."

# Dump User List
echo "Dumping User List..."
cut -d: -f1 /etc/passwd > UserList.txt
echo "User list saved to UserList.txt"
cat UserList.txt

# Dump User Privileges
echo "Dumping User Privileges..."
while IFS=: read -r user _; do
    echo "User: $user"
    groups "$user"
    echo
done < <(cut -d: -f1 /etc/passwd) > UserPrivileges.txt
echo "User privileges saved to UserPrivileges.txt"

# Disable Guest User Accounts
echo "Disabling Guest Users..."
for guest_user in $(grep -E 'guest' /etc/passwd | cut -d: -f1); do
    usermod -L "$guest_user" && echo "Disabled guest user: $guest_user" || echo "Failed to disable: $guest_user"
done
echo "Guest user accounts processed."

# Dump Groups and Members
echo "Dumping Groups and Members..."
getent group | awk -F: '{print $1}' > GroupList.txt
echo "Group list saved to GroupList.txt"
while IFS=: read -r group_name _; do
    echo "Group: $group_name"
    getent group "$group_name" | cut -d: -f4
    echo
done < GroupList.txt > GroupPrivileges.txt
echo "Group privileges saved to GroupPrivileges.txt"

# Password Rule Enforcement
echo "Enforcing password rules..."
sed -i '/^PASS_MIN_LEN/d' /etc/login.defs
echo "PASS_MIN_LEN 12" >> /etc/login.defs
sed -i '/^PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS 30" >> /etc/login.defs
sed -i '/^PASS_MIN_DAYS/d' /etc/login.defs
echo "PASS_MIN_DAYS 5" >> /etc/login.defs
echo "Password policy updated."

# Dump Running Processes
echo "Dumping running processes..."
ps aux --sort=-%cpu > RunningProcesses.txt
echo "Running processes saved to RunningProcesses.txt"

# List Enabled Services
echo "Dumping enabled services..."
systemctl list-unit-files | grep enabled > EnabledServices.txt
echo "Enabled services saved to EnabledServices.txt"

# Dump Scheduled Tasks
echo "Dumping scheduled tasks..."
crontab -l > ScheduledTasks.txt 2>/dev/null
echo "Scheduled tasks saved to ScheduledTasks.txt"

# Disable Unnecessary Services
echo "Disabling unnecessary services..."
UNNECESSARY_SERVICES=(
    "telnet" "ftp" "rlogin" "rsh"
)
for service in "${UNNECESSARY_SERVICES[@]}"; do
    systemctl disable "$service" --now 2>/dev/null && echo "Disabled $service" || echo "$service not found or already disabled."
done

# Search for Potential Threat Tools
echo "Searching for potential threat tools..."
THREAT_TOOLS=("nmap" "john" "nikto" "metasploit" "mimikatz")
for tool in "${THREAT_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "Tool detected: $tool. Investigate further."
    else
        echo "$tool not installed."
    fi
done

# System File Hash Validation
echo "Validating system file hashes..."
find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} \; > SystemFileHashes.txt
echo "System file hashes saved to SystemFileHashes.txt"

# Enable Firewall
echo "Enabling and configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw enable
echo "Firewall enabled and configured."


# Config SSH

echo "Configuring SSH security settings..."
sed -i '/^PermitRootLogin /d' /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
sed -i '/^PermitEmptyPasswords /d' /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
sed -i '/^PubkeyAuthentication /d' /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
sed -i '/^X11Forwarding /d' /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
sed -i '/^ClientAliveInterval /d' /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "SSH security settings applied."

# Config Firewall
echo "Configuring firewall settings..."

# Set default policies
ufw default deny incoming comment "Deny all incoming traffic by default"
ufw default allow outgoing comment "Allow all outgoing traffic by default"

# Allow SSH on port 22 (modify if SSH is on a different port)
ufw allow 22/tcp comment "Allow SSH"

# Allow HTTPS traffic for secure web servers
ufw allow 443/tcp comment "Allow HTTPS"

# Allow DNS traffic for name resolution
ufw allow 53/udp comment "Allow DNS"

# Block Ping (ICMP Echo Request)
echo "Blocking ping (ICMP)..."
ufw deny from any to any proto icmp comment "Block ICMP"

# Enable logging of denied connections
echo "Enabling UFW logging for denied connections..."
ufw logging on

# Enable the firewall
echo "Enabling the firewall..."
ufw enable

echo "Firewall configuration completed."

# Config Samba
echo "Configuring Samba security settings..."
SAMBA_CONF="/etc/samba/smb.conf"
if [[ -f "$SAMBA_CONF" ]]; then
    sed -i '/\[global\]/a \
    client min protocol = SMB2\n\
    server min protocol = SMB2\n\
    restrict anonymous = 2\n\
    ntlm auth = no\n\
    smb encrypt = required\n\
    null passwords = no\n' "$SAMBA_CONF"
    systemctl restart smbd
    echo "Samba settings hardened."
else
    echo "Samba configuration file not found. Skipping Samba hardening."
fi


# PHP Hardening
echo "Configuring PHP security settings..."
PHP_INI="/etc/php/7.4/apache2/php.ini"
if [[ -f "$PHP_INI" ]]; then
    sed -i 's/^expose_php =.*/expose_php = Off/' "$PHP_INI"
    sed -i 's/^display_errors =.*/display_errors = Off/' "$PHP_INI"
    sed -i 's/^allow_url_fopen =.*/allow_url_fopen = Off/' "$PHP_INI"
    sed -i 's/^allow_url_include =.*/allow_url_include = Off/' "$PHP_INI"
    sed -i 's/^disable_functions =.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen/' "$PHP_INI"
    echo "PHP settings hardened."
else
    echo "PHP configuration file not found. Skipping PHP hardening."
fi
