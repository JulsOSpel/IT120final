#!/bin/bash
### RedHat Security patchs ###
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
    dnf update >> PachTuxLog/update.txt 2>/dev/null
    echo -e "$aro2${nor} Update done! Check update.txt in PachTuxLog for errors."
    sleep 2
    echo ""
else
    echo "No update"
fi
echo -e "$aro2${nor} Not finished! ):"
exit
