#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Simple test menu
clear
echo -e "${GREEN}=== VPS Management Menu ===${NC}"
echo -e "1) Test Option"
echo -e "2) Exit"
read -p "Select an option: " choice

case $choice in
    1) echo "Menu is working!" ;;
    2) exit 0 ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac 