#!/usr/pkg/bin/bash
bold=$(tput bold)
normal=$(tput sgr0)

printf "${bold}Executing telnet for time.. ${normal}\n"
telnet fd10:2020:c5c1:367:e15f:7bc8:97a3:cf9d 13

printf "\n"
printf "${bold}Executing telnet for quote of the day...${normal}\n"
telnet fd10:2020:c5c1:367:e15f:7bc8:97a3:cf9d 17

printf "\n"
printf "${bold}Executing netstat...${normal}\n"
netstat -nf inet6

printf "\n"
printf "${bold}Executing netstat with -a flag...${normal}\n"
netstat -anf inet6
printf "\n"

