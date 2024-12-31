if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root."
    exit 1
fi

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