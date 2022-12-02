#!/bin/bash
### Ubuntu Security Patches ###
user=$(whoami) # Print username
int=""
# Format
aro="\033[1;34m➜" # Light blue arrow bold
aro2="\033[1;32m➜" # Light green arrow bold
nor="\033[0;1m" # Normal text
red="\033[1;31m" # Red color
err="\033[1;34m➜\033[1;31m Error!" # Error text
# Make file to store log data
mkdir PachTuxLog 2>/dev/null
# Check for updates & output data to PachTuxLog
echo -e "$aro${nor} Hey $user, Want to check for updates? y/n" # Confirm user wants to update
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]] 
then
    echo -e "$aro2${nor} 1.9 Ensure updates, patches, and additional security software are installed"
    apt update >> PachTuxLog/update.txt 2>/dev/null && apt -y upgrade >> PachTuxLog/update.txt 2>/dev/null
    echo -e "$aro2${nor} Update done! Check update.txt in PachTuxLog for errors."
    sleep 2
    echo ""
    echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.1? y/n"
else
    echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.1? y/n"
fi
# +=== Full auto patch of CIS 1.1 ===+
# This if statement outlines disabling the mounting different file systems
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]] 
then
    echo -e "$aro2${nor} 1.1.1.1 Ensure mounting of cramfs filesystems is disabled."
    {
        l_mname="cramfs" # set module name
        if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install\/bin\/(true|false)'; then
            echo -e " - setting module: \"$l_mname\" to be not loadable"
            echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
        fi
        if lsmod | grep "$l_mname" > /dev/null 2>&1; then
            echo -e " - unloading module \"$l_mname\""
            modprobe -r "$l_mname"
        fi
        if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
            echo -e " - deny listing \"$l_mname\""
            echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
        fi 
    }
    echo -e "$aro2${nor} 1.1.1.2 Ensure mounting of squashfs filesystems is disabled."
    {
        s_mname="squashfs" # set module name
        if ! modprobe -n -v "$s_mname" | grep -P -- '^\h*install\/bin\/(true|false)'; then
            echo -e " - setting module: \"$s_mname\" to be not loadable"
            echo -e "install $s_mname /bin/false" >> /etc/modprobe.d/"$s_mname".conf
        fi
        if lsmod | grep "$s_mname" > /dev/null 2>&1; then
            echo -e " - unloading module \"$s_mname\""
            modprobe -r "$s_mname"
        fi
        if ! grep -Pq -- "^\h*blacklist\h+$s_mname\b" /etc/modprobe.d/*; then
            echo -e " - deny listing \"$s_mname\""
            echo -e "blacklist $s_mname" >> /etc/modprobe.d/"$s_mname".conf
        fi
    }
    echo -e "$aro2${nor} 1.1.1.3 Ensure mounting of udf filesystems is disabled."
    {
         u_mname="udf" # set module name
         if ! modprobe -n -v "$u_mname" | grep -P -- '^\h*install\/bin\/(true|false)'; then
             echo -e " - setting module: \"$u_mname\" to be not loadable"
             echo -e "install $u_mname /bin/false" >> /etc/modprobe.d/"$u_mname".conf
         fi
         if lsmod | grep "$u_mname" > /dev/null 2>&1; then
             echo -e " - unloading module \"$u_mname\""
             modprobe -r "$u_mname"
         fi
         if ! grep -Pq -- "^\h*blacklist\h+$u_mname\b" /etc/modprobe.d/*; then
             echo -e " - deny listing \"$u_mname\""
             echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$u_mname".conf
         fi
    }
    echo -e "$aro2${red} 1.1.2 through 1.1.8 should be done manually.${nor}"
else
    echo -e "$aro2${nor} Skipping most of CIS 1.1"
fi
# This if statement will lockout the ability to remove removable media
echo -e "$aro${nor} Would you like to lockout removable media? y/n."
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]] 
then
    echo -e "$aro2${nor} 1.1.9 Disable Automounting."
    systemctl stop autofs
    sleep 1
    systemctl mask autofs
    echo -e "$aro2${nor} 1.1.10 Disable USB Storage."
    {
        b_mname="usb-storage" # set module name
        if ! modprobe -n -v "$b_mname" | grep -P -- '^\h*install\/bin\/(true|false)'; then
            echo -e " - setting module: \"$b_mname\" to be not loadable"
            echo -e "install $b_mname /bin/false" >> /etc/modprobe.d/"$b_mname".conf
        fi
        if lsmod | grep "$b_mname" > /dev/null 2>&1; then
            echo -e " - unloading module \"$b_mname\""
            modprobe -r "$b_mname"
        fi
        if ! grep -Pq -- "^\h*blacklist\h+$b_mname\b" /etc/modprobe.d/*; then
            echo -e " - deny listing \"$b_mname\""
            echo -e "blacklist $b_mname" >> /etc/modprobe.d/"$b_mname".conf
        fi
    }
else
    echo -e "$aro2${nor} Skipping lockout of removable media."
fi
# +=== Full auto patch of CIS 1.2 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.2? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]] 
then
    echo -e "$aro2${nor} 1.2.1 Ensure package manager repositories are configured"
    echo -e "$aro${red} You can review your current repository's in policy.txt${nor}"
    apt-cache policy >> PachTuxLog/policy.txt 2>/dev/null
    sleep 2
    echo -e "$aro2${nor} 1.2.2 Ensure GPG keys are configured."
    echo -e "$aro${red} You can review your current GPG keys in key.txt${nor}"
    apt-key list >> PachTuxLog/key.txt 2>/dev/null
    sleep 2
    echo echo -e "$aro2${nor} When you are done reviewing you can continue."
else
    echo -e "$aro2${nor} Skipping CIS 1.2"
fi
# +=== Full auto patch of CIS 1.3 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.3? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 1.3.1 Ensure AIDE is installed"
    apt -y install aide aide-common
    aideinit >> PachTuxLog/aide.txt 2>/dev/null
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db >> PachTuxLog/aide.txt 2>/dev/null
    echo -e "$aro${red} You can review AIDE install in aide.txt${nor}"
    echo -e "$aro2${nor} 1.3.2 Ensure filesystem integrity is regularly checked"
    cp PatchTuxData/systemd/aidecheck.service /etc/systemd/system/aidecheck.service
    cp PatchTuxData/systemd/aidecheck.timer /etc/systemd/system/aidecheck.timer
    chown root:root /etc/systemd/system/aidecheck.*
    chmod 0644 /etc/systemd/system/aidecheck.*
    sleep 1
    systemctl daemon-reload
    systemctl enable aidecheck.service
    systemctl --now enable aidecheck.timer
else
    echo -e "$aro2${nor} Skipping CIS 1.3"
fi
# +=== Full auto patch of CIS 1.4 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.4? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 1.4.1 Ensure bootloader password is set"
    echo -e "$aro${nor} Enter a password for grub hash."
    grub-mkpasswd-pbkdf2
    echo -e "$aro${nor} Enter a name for the admin account"
    read int2 # read username
    echo -e "$aro${nor} Enter the hash."
    read int # read hash
    echo "cat << EOF" >> /etc/grub.d/00_header
    echo "set superusers="$int2"" >> /etc/grub.d/00_header
    echo "password_pbkdf2 $int2 $int EOF" >> /etc/grub.d/00_header
    sed -i 's/CLASS="--class gnu-linux --class gnu --class os"/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/g' /etc/grub.d/10_linux
    echo -e "$aro2${nor} Updating grub."
    update-grub
    echo -e "$aro2${nor} 1.4.2 Ensure permissions on bootloader config are configured"
    chown root:root /boot/grub/grub.cfg
    chmod u-wx,go-rwx /boot/grub/grub.cfg
    echo -e "$aro2${nor} 1.4.3 Ensure authentication required for single user mode"
    echo -e "$aro${nor} Enter a password for root"
    passwd root
else
    echo -e "$aro2${nor} Skipping CIS 1.4"
fi
# +=== Full auto patch of CIS 1.5 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.5? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 1.5.1 Ensure address space layout randomization (ASLR) is enabled"
    printf "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf
    sysctl -w kernel.randomize_va_space=2
    echo -e "$aro2${nor} 1.5.2 Ensure prelink is not installed"
    prelink -ua >> PachTuxLog/link.txt
    apt -y purge prelink
    echo -e "$aro2${nor} Check link.txt in PachTuxLog for errors."
    echo -e "$aro2${nor} 1.5.3 Ensure Automatic Error Reporting is not enabled"
    sed -i 's/enabled=1/enabled=0/g' /etc/default/apport
    systemctl stop apport.service
    systemctl --now disable apport.service
    echo -e "$aro2${nor} 1.5.4 Ensure core dumps are restricted"
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sysctl -w fs.suid_dumpable=0
else
    echo -e "$aro2${nor} Skipping CIS 1.5"
fi
# +=== Full auto patch of CIS 1.6 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.6? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro${nor} Hey $user, Do you not have AppArmor installed? Say n to skip install. y/n"
    read int
    if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
    then
        echo -e "$aro2${nor} 1.6.1.1 Ensure AppArmor is installed"
        apt -y install apparmor
        apt -y install apparmor-profiles apparmor-utils
        echo -e "$aro2${nor} 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration"
        sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/g' /etc/default/grub
        update-grub
        echo echo -e "$aro2${nor} Reboot system and skip AppArmor installation."
        exit
    else
        echo echo -e "$aro2${nor} Skipping AppArmor installation."
    fi
    echo -e "$aro2${nor} 1.6.1.3/1.6.1.4 Ensure all AppArmor Profiles are in enforce mode"
    aa-enforce /etc/apparmor.d/*
else
    echo -e "$aro2${nor} Skipping CIS 1.6"
fi
# +=== Full auto patch of CIS 1.7 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.7? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 1.7.1 Ensure message of the day is configured properly"
    touch /etc/motd
    echo "Gamer users only. All activity may be monitored and reported. (;" > /etc/moted
    echo -e "$aro2${nor} 1.7.2 Ensure local login warning banner is configured properly"
    echo "Gamer users only. All activity may be monitored and reported. (;" > /etc/issue
    echo -e "$aro2${nor} 1.7.3 Ensure remote login warning banner is configured properly"
    echo "Gamer users only. All activity may be monitored and reported. (;" > /etc/issue.net
    echo -e "$aro2${nor} 1.7.4 Ensure permissions on /etc/motd are configured"
    chown root:root /etc/motd
    chmod u-x,go-wx /etc/motd
    echo -e "$aro2${nor} 1.7.5 Ensure permissions on /etc/issue are configured"
    chown root:root /etc/issue
    chmod u-x,go-wx /etc/issue
    echo -e "$aro2${nor} 1.7.6 Ensure permissions on /etc/issue.net are configured"
    chown root:root /etc/issue.net
    chmod u-x,go-wx /etc/issue.net
else
    echo -e "$aro2${nor} Skipping CIS 1.7"
fi
# +=== Full auto patch of CIS 1.8 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 1.8? y/n"
echo -e "$aro${nor} ${red}NOTE: This will uninstall gnome desktop!${nor}"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 1.8.1/1.8.10 Ensure GNOME Display Manager is removed"
    apt -y purge gdm3 >> PachTuxLog/RemoveDesktop.txt
    apt -y purge xserver-xorg* >> PachTuxLog/RemoveDesktop.txt
else
    echo -e "$aro2${nor} Skipping CIS 1.8"
fi
# +=== Full auto patch of CIS 2.1 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 2.1? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 2.1.1.1 Ensure a single time synchronization daemon is in use"
    apt -y install chrony >> PachTuxLog/chrony.txt
    systemctl stop systemd-timesyncd.service
    systemctl --now mask systemd-timesyncd.service
    apt -y purge ntp >> PachTuxLog/chrony.txt
    echo -e "$aro2${nor} 2.1.2.1 Ensure chrony is configured with authorized timeserver"
    echo -e "$aro2${nor} 2.1.2.2 Ensure chrony is running as user _chrony"
    cp PatchTuxData/chrony/chrony.conf /etc/chrony/
    echo -e "$aro2${nor} 2.1.2.3 Ensure chrony is enabled and running"
    systemctl unmask chrony.service
    systemctl --now enable chrony.service
    systemctl restart chrony.service
    sleep 2
    chronyc authdata -v >> PachTuxLog/chrony.txt
    # We skip the other NTP services as we are using chrony
else
    echo -e "$aro2${nor} Skipping CIS 2.1"
fi
# +=== Full auto patch of CIS 2.2 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 2.2? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    # We skip 2.2.1 as this was done in 1.8.1/1.8.10
    echo -e "$aro2${nor} 2.2.2 Ensure Avahi Server is not installed"
    systemctl stop avahi-daaemon.service >> PachTuxLog/avahi.txt
    systemctl stop avahi-daemon.socket >> PachTuxLog/avahi.txt
    apt -y purge avahi-daemon >> PachTuxLog/avahi.txt
    # Decided to skip theses steps
else
    echo -e "$aro2${nor} Skipping CIS 2.2"
fi
# +=== Full auto patch of CIS 2.3 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 2.3? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 2.3.1 Ensure NIS Client is not installed"
    apt -y purge nis >> PachTuxLog/UninstallServiceClients.txt
    echo -e "$aro2${nor} 2.3.2 Ensure rsh client is not installed"
    apt -y purge rsh-client >> PachTuxLog/UninstallServiceClients.txt
    echo -e "$aro2${nor} 2.3.3 Ensure talk client is not installed"
    apt -y purge talk >> PachTuxLog/UninstallServiceClients.txt
    echo -e "$aro2${nor} 2.3.4 Ensure telnet client is not installed"
    apt -y purge telnet >> PachTuxLog/UninstallServiceClients.txt
    echo -e "$aro2${nor} 2.3.6 Ensure RPC is not installed"
    apt -y purge rpcbind >> PachTuxLog/UninstallServiceClients.txt
else
    echo -e "$aro2${nor} Skipping CIS 2.3"
fi
# +=== CIS 2.3 ===+
echo -e "$aro2${nor} 2.4 Ensure nonessential services are removed or masked"
sleep 2
vi PatchTuxData/2.4.txt
echo -e "$aro2${nor} You can review this more in PatchTuxData/2.4.txt"
sleep 2
# +=== Full auto patch of CIS 3.1 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 3.1? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 3.1.1 Ensure system is checked to determine if IPv6 is enabled"
    if [ grep "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"" /etc/default/grub = "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"" ]; 
    then
        sed -i 's/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor ipv6.disable=1"/g' /etc/default/grub
        update-grub
    else
        sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/g' /etc/default/grub
        update-grub
    fi
    echo -e "$aro2${nor} 3.1.2 Ensure wireless interfaces are disabled"
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
            for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi
else
    echo -e "$aro2${nor} Skipping CIS 3.1"
fi
# +=== Full auto patch of CIS 3.2 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 3.2? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 3.2.1 Ensure packet redirect sending is disabled"
    # FIXME
    echo -e "$aro2${nor} 3.2.2 Ensure IP forwarding is disabled"
    # FIXME
else           
    echo -e "$aro2${nor} Skipping CIS 3.2"
fi
# +=== Full auto patch of CIS 3.3 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 3.3? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 3.3.1 Ensure source routed packets are not accepted"
    {
        pc_output="" pc_output2=""
        pc_parlist="net.ipv4.conf.all.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0"
        pc_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
        KPF()
        {
            # comment out incorrect parameter(s) in kernel parameter file(s)
            pc_fafile="$(grep -s -- "^\s*$pc_kpname" $pc_searchloc | grep -Pv -- "\h*=\h*$pc_kpvalue\b\h*" | awk -F: '{print $1}')"
            for pc_bkpf in $pc_fafile; do
                echo -e "\n - Commenting out \"$pc_kpname\" in \"$pc_bkpf\""
                sed -ri "/$pc_kpname/s/^/# /" "$pc_bkpf"
            done
            # Set correct parameter in a kernel parameter file
            if ! grep -Pslq -- "^\h*$pc_kpname\h*=\h*$pc_kpvalue\b\h*(#.*)?$"$pc_searchloc; then
                echo -e "\n - Setting \"$pc_kpname\" to \"$pc_kpvalue\" in \"$pc_kpfile\""
            fi
            # Set correct parameter in active kernel parameters
            pc_krp="$(sysctl "$pc_kpname" | awk -F= '{print $2}' | xargs)"
            if [ "$pc_krp" != "$pc_kpvalue" ]; then
                echo -e "\n - Updating \"$pc_kpname\" to \"$pc_kpvalue\" in the active kernel parameters"
                sysctl -w "$pc_kpname=$pc_kpvalue"
                sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$pc_kpname")"
            fi
        }
        IPV6F_CHK()
        {
            pc_ipv6s=""
            agrubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {}\;)
            if [ -s "$agrubfile" ]; then
                ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$agrubfile" | grep -vq -- ipv6.disable=1 && pc_ipv6s="disabled"
            fi
            if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $pc_searchloc && \
                grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $pc_searchloc && \
                sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
                sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
                pc_ipv6s="disabled"
            fi
            if [ -n "$pc_ipv6s" ]; then
                echo -e "\n - IPv6 is disabled on the system, \"$pc_kpname\" is not applicable"
            else
                KPF
            fi
        }
        for pc_kpe in $pc_parlist; do
            pc_kpname="$(awk -F= '{print $1}' <<< "$pc_kpe")"
            pc_kpvalue="$(awk -F= '{print $2}' <<< "$pc_kpe")"
            if grep -q '^net.ipv6.' <<< "$pc_kpe"; then
                pc_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
                IPV6F_CHK
            else
                pc_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            fi
        done
    }
    echo -e "$aro2${nor} 3.3.2 Ensure ICMP redirects are not accepted"
    {
         ac_output="" ac_output2=""
         ac_parlist="net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0"
         ac_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
         KPF()
         {
             # comment out incorrect parameter(s) in kernel parameter file(s)
             ac_fafile="$(grep -s -- "^\s*$ac_kpname" $ac_searchloc | grep -Pv -- "\h*=\h*$ac_kpvalue\b\h*" | awk -F: '{print $1}')"
             for ac_bkpf in $ac_fafile; do
                 echo -e "\n - Commenting out \"$ac_kpname\" in \"$ac_bkpf\""
                 sed -ri "/$ac_kpname/s/^/# /" "$ac_bkpf"
             done
             # Set correct parameter in a kernel parameter file
             if ! grep -Pslq -- "^\h*$ac_kpname\h*=\h*$ac_kpvalue\b\h*(#.*)?$" $ac_searchloc; then
                 echo -e "\n - Setting \"$ac_kpname\" to \"$ac_kpvalue\" in \"$ac_kpfile\""
                 echo "$ac_kpname = $ac_kpvalue" >> "$ac_kpfile"
             fi
             # Set correct parameter in active kernel parameters
             _krp="$(sysctl "$ac_kpname" | awk -F= '{print $2}' | xargs)"
             if [ "$ac_krp" != "$ac_kpvalue" ]; then
                 echo -e "\n - Updating \"$ac_kpname\" to \"$ac_kpvalue\" in the active kernel parameters"
                 sysctl -w "$ac_kpname=$ac_kpvalue"
                 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$ac_kpname")"
             fi
         }
         IPV6F_CHK()
         {
             ac_ipv6s=""
             bgrubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {}\;)
             if [ -s "$bgrubfile" ]; then
                 ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$bgrubfile" | grep -vq -- ipv6.disable=1 && ac_ipv6s="disabled"
             fi
             if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $ac_searchloc && \
                 grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $ac_searchloc && \
                 sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
                 sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
                 ac_ipv6s="disabled"
             fi
             if [ -n "$ac_ipv6s" ]; then
                 echo -e "\n - IPv6 is disabled on the system, \"$ac_kpname\" is not applicable"
             else
                 KPF
             fi
         }
         for ac_kpe in $ac_parlist; do
             ac_kpname="$(awk -F= '{print $1}' <<< "$ac_kpe")"
             ac_kpvalue="$(awk -F= '{print $2}' <<< "$ac_kpe")"
             if grep -q '^net.ipv6.' <<< "$ac_kpe"; then
                 ac_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
                 IPV6F_CHK
             else
                 ac_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
                 KPF
             fi
         done
    }
    echo -e "$aro2${nor} 3.3.3 Ensure secure ICMP redirects are not accepted"
    kernel_parameter_fix()
    {
        bc_output="" bc_output2=""
        bc_parlist="net.ipv4.conf.default.secure_redirects=0 net.ipv4.conf.all.secure_redirects=0"
        bc_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
        bc_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
        KPF()
        {
            # comment out incorrect parameter(s) in kernel parameter file(s)
            bc_fafile="$(grep -s -- "^\s*$bc_kpname" $bc_searchloc | grep -Pv -- "\h*=\h*$bc_kpvalue\b\h*" | awk -F: '{print $1}')"
            for bc_bkpf in $bc_fafile; do
                echo -e "\n - Commenting out \"$bc_kpname\" in \"$bc_bkpf\""
                sed -ri "/$bc_kpname/s/^/# /" "$bc_bkpf"
            done
                # Set correct parameter in a kernel parameter file
            if ! grep -Pslq -- "^\h*$bc_kpname\h*=\h*$bc_kpvalue\b\h*(#.*)?$" $bc_searchloc; then
                echo -e "\n - Setting \"$bc_kpname\" to \"$bc_kpvalue\" in \"$bc_kpfile\""
                echo "$bc_kpname = $bc_kpvalue" >> "$bc_kpfile"
            fi
            # Set correct parameter in active kernel parameters
            bc_krp="$(sysctl "$bc_kpname" | awk -F= '{print $2}' | xargs)"
            if [ "$bc_krp" != "$bc_kpvalue" ]; then
                echo -e "\n - Updating \"$bc_kpname\" to \"$bc_kpvalue\" in the active kernel parameters"
                sysctl -w "$bc_kpname=$bc_kpvalue"
                sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$bc_kpname")"
            fi
        }
        for bc_kpe in $bc_parlist; do
            bc_kpname="$(awk -F= '{print $1}' <<< "$bc_kpe")"
            bc_kpvalue="$(awk -F= '{print $2}' <<< "$bc_kpe")"
            KPF
        done
    }
    echo -e "$aro2${nor} 3.3.4 Ensure suspicious packets are logged"
else
    echo -e "$aro2${nor} Skipping CIS 3.2"
fi
# I will go back to the others
# +=== Full auto patch of CIS 3.5 ===+
echo -e "$aro${nor} Hey $user, Want to secure the system with CIS step 3.5? y/n"
echo -e "$aro${nor} ${red}NOTE: Be sure to have your ports open that you need open.${nor}"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro2${nor} 3.5.1.1 Ensure ufw is installed"
    apt -y install ufw >> PachTuxLog/ufw.txt
    echo -e "$aro2${nor} 3.5.1.2 Ensure iptables-persistent is not installed with ufw"
    apt -y purge iptables-persistent >> PachTuxLog/ufw.txt
    echo -e "$aro2${nor} 3.5.1.3 Ensure ufw service is enabled"
    systemctl unmask ufw.service
    systemctl --now enable ufw.service
    ufw enable
    echo -e "$aro2${nor} 3.5.1.4 Ensure ufw loopback traffic is configured"
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    echo -e "$aro2${nor} 3.5.1.5 Ensure ufw outbound connections are configured"
    ufw allow out on all
    echo -e "$aro2${nor} 3.5.1.6 Ensure ufw firewall rules exist for all open ports"
    echo -e "$aro${nor} ufw allow in <port>/<tcp or udp protocol>"
    sleep 2
    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny routed
else
    echo -e "$aro2${nor} Skipping CIS 3.5"
fi
