#!/bin/bash

user=$(whoami) # Print username
int=""
# Format
aro="\033[1;34m➜" # Light blue arrow bold
aro2="\033[1;32m➜" # Light green arrow bold
nor="\033[0;1m" # Normal text
red="\033[1;31m" # Red color
err="\033[1;34m➜\033[1;31m Error!" # Error text
# Program name & info
echo -e "${nor}+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+${red}

 ██▓███   ▄▄▄     ▄▄▄█████▓ ▄████▄   ██░ ██    ▄▄▄█████▓ █    ██ ▒██   ██▒
▓██░  ██▒▒████▄   ▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒   ▓  ██▒ ▓▒ ██  ▓██▒▒▒ █ █ ▒░
▓██░ ██▓▒▒██  ▀█▄ ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░   ▒ ▓██░ ▒░▓██  ▒██░░░  █   ░
▒██▄█▓▒ ▒░██▄▄▄▄██░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██    ░ ▓██▓ ░ ▓▓█  ░██░ ░ █ █ ▒ 
▒██▒ ░  ░ ▓█   ▓██▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓     ▒██▒ ░ ▒▒█████▓ ▒██▒ ▒██▒
▒▓▒░ ░  ░ ▒▒   ▓▒█░ ▒ ░░   ░ ░▒ ▒  ░ ▒ ░░▒░▒     ▒ ░░   ░▒▓▒ ▒ ▒ ▒▒ ░ ░▓ ░
░▒ ░       ▒   ▒▒ ░   ░      ░  ▒    ▒ ░▒░ ░       ░    ░░▒░ ░ ░ ░░   ░▒ ░
░░         ░   ▒    ░      ░         ░  ░░ ░     ░       ░░░ ░ ░  ░    ░  
               ░  ░        ░ ░       ░  ░  ░               ░      ░    ░  
                           ░                                              

      ${nor}:0:${red}Patch Tux is a program used to patch Linux based systems.${nor}:0:
      ${nor}:0:${red}        Supported distros are RHEL, and Ubuntu.          ${nor}:0:
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+"
# Check for root
if ! [ $(id -u) = 0 ]; then
    echo -e "$err Sorry $user you are not in root ):" && exit
fi
# Confirm user wants to run the script
echo -e "$aro${nor} Hello $user! Ready to get patched? y/n"
read int
if [[ $int =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo -e "$aro${nor} Hey $user, What distro do you use? Ubuntu=1 RHEL=2" # Check what distro the user uses
else
    echo -e "$aro${nor} Okay, Bye $user." && exit
fi
# Select distro based on input taken
read int
if [[ ${int} == "1" ]]; then
    chmod +x PatchTuxData/Ubuntu.sh
    ./PatchTuxData/Ubuntu.sh # Start into the Ubuntu security script
elif [[ ${int} = "2" ]]; then
    chmod +x PatchTuxData/RedHat.sh
    ./PatchTuxData/RedHat.sh # Start into the RedHat security script
else
    echo -e "$err Not a valid input."
fi
