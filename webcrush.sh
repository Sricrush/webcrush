#!/bin/bash

# =========================================
# WEB + SSL/TLS SECURITY SCANNER
# Author : srinath.k
# Platform : Kali Linux / Linux
# =========================================

# ------------ Colors -------------
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

# ------------ Silent Tool Check -------------
check_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Installing missing tool: $2${NC}"
        sudo apt update -y >/dev/null 2>&1
        sudo apt install -y "$2" >/dev/null 2>&1
    fi
}

check_tool curl curl
check_tool sslyze sslyze

# ==============================
# WEBCRUSH-STYLE BANNER
# ==============================
echo -e "${CYAN}"
cat << "EOF"
 __        __   _     ____                _
 \ \      / /__| |__ / ___|_ __ _   _ ___| |__
  \ \ /\ / / _ \ '_ \ |   | '__| | | / __| '_ \
   \ V  V /  __/ |_) | |___| |  | |_| \__ \ | | |
    \_/\_/ \___|_.__/ \____|_|   \__,_|___/_| |_|

EOF
echo -e "${WHITE}   Web & SSL Vulnerability Scanner (Kali Linux)"
echo -e "${YELLOW}   Author : Srinath.K${RESET}"
echo

# ------------ Input -------------
DOMAINS=()

if [ "$1" = "-f" ] && [ -f "$2" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] && DOMAINS+=("$line")
    done < "$2"
elif [ $# -ge 1 ]; then
    DOMAINS=("$@")
else
    read -p "Enter the URL(s) (space separated): " INPUT
    DOMAINS=($INPUT)
fi

if [ ${#DOMAINS[@]} -eq 0 ]; then
    echo -e "${RED}No domains provided. Exiting.${NC}"
    exit 1
fi

# ------------ Domain Loop -------------
for TARGET in "${DOMAINS[@]}"; do
    TARGET_NOPROTO=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')
    echo -e "\n${CYAN}======================"
    echo "Scanning: $TARGET_NOPROTO"
    echo "======================${NC}"

    # ----------------- Fetch Headers -----------------
    HEADERS=$(curl -s -I -k "$TARGET" 2>/dev/null)

    # ----------------- Security Headers -----------------
    echo -e "${BLUE}Checking Security Headers${NC}\n"
    MISSING_HEADERS=()
    check_header() {
        echo "$HEADERS" | grep -qi "$1" || MISSING_HEADERS+=("$2")
    }

    check_header "Strict-Transport-Security" "Strict-Transport-Security header is not implemented"
    check_header "Content-Security-Policy" "Content-Security-Policy header is not implemented"
    check_header "X-Frame-Options" "X-Frame-Options header is not implemented"
    check_header "X-Content-Type-Options" "X-Content-Type-Options header is not implemented"
    check_header "Referrer-Policy" "Referrer-Policy header is not implemented"

    if [ ${#MISSING_HEADERS[@]} -eq 5 ]; then
        echo -e "${RED}No security headers are present.${NC}\n"
    else
        echo -e "${YELLOW}Some security headers are present.${NC}\n"
    fi

    echo "Missing headers:"
    for h in "${MISSING_HEADERS[@]}"; do
        echo "$h"
    done

    # ----------------- Server & X-Powered-By -----------------
    echo -e "\n${BLUE}Checking Server Header disclosure${NC}"
    SERVER=$(echo "$HEADERS" | grep -i "^Server:")
    [ -n "$SERVER" ] && echo -e "${RED}Server header is disclosed:${NC} ${SERVER#Server: }" || echo -e "${GREEN}Server header is not disclosed.${NC}"

    echo -e "\n${BLUE}Checking X-Powered-By Header disclosure${NC}"
    XPB=$(echo "$HEADERS" | grep -i "^X-Powered-By:")
    [ -n "$XPB" ] && echo -e "${RED}X-Powered-By header is disclosed:${NC} ${XPB#X-Powered-By: }" || echo -e "${GREEN}X-Powered-By header is not disclosed.${NC}"

    # ----------------- OPTIONS Method -----------------
    echo -e "\n${BLUE}Checking for OPTIONS method${NC}"
    OPTIONS=$(curl -s -X OPTIONS -I -k "$TARGET")
    echo "$OPTIONS" | grep -qi "^Allow" && echo -e "${RED}OPTIONS method is Enabled.${NC}" || echo -e "${GREEN}OPTIONS method is not Enabled.${NC}"

    # ----------------- Cookies -----------------
    echo -e "\n${BLUE}Checking Cookie flags${NC}"
    COOKIES=$(echo "$HEADERS" | grep -i "Set-Cookie")
    if [ -z "$COOKIES" ]; then
        echo -e "${GREEN}No cookies are set.${NC}"
    else
        echo "$COOKIES"
        echo "$COOKIES" | grep -qi "secure" || echo -e "${RED}Cookie without Secure flag detected.${NC}"
        echo "$COOKIES" | grep -qi "httponly" || echo -e "${RED}Cookie without HttpOnly flag detected.${NC}"
    fi

    # ----------------- HEADER & OPTION POC -----------------
    echo -e "\n${BLUE}HEADER POC${NC}"
    curl "$TARGET" -I -k
    echo -e "\n${GREEN}Command executed successfully.${NC}"

    echo -e "\n${BLUE}OPTION POC${NC}"
    curl -X OPTIONS "$TARGET" -I -k
    echo -e "\n${GREEN}Command executed successfully.${NC}"

    # ----------------- SSL/TLS CHECK -----------------
    echo -e "\n${CYAN}Checking SSL/TLS Vulnerabilities using SSLYZE${NC}"
    SSLYZE_OUTPUT=$(PYTHONWARNINGS="ignore" sslyze \
        --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
        --heartbleed --compression --robot --openssl_ccs --reneg --certinfo \
        "$TARGET_NOPROTO:443" 2>/dev/null)

    # Print full SSLyze output
    echo -e "\n${BLUE}--- FULL SSLyze OUTPUT ---${NC}"
    echo "$SSLYZE_OUTPUT"
    echo -e "${BLUE}--- END OF SSLyze OUTPUT ---${NC}\n"

    # -------- Extract Vulnerabilities ----------
    VULN_FOUND=false
    # TLS versions
    echo "$SSLYZE_OUTPUT" | grep -q "TLS 1.0 Cipher Suites" && echo -e "${RED}[!] Weak TLS Version: TLS 1.0${NC}" && VULN_FOUND=true
    echo "$SSLYZE_OUTPUT" | grep -q "TLS 1.1 Cipher Suites" && echo -e "${RED}[!] Weak TLS Version: TLS 1.1${NC}" && VULN_FOUND=true
    # Weak ciphers
    WEAK_CIPHERS=$(echo "$SSLYZE_OUTPUT" | grep -E "CBC_SHA|3DES_EDE")
    if [ -n "$WEAK_CIPHERS" ]; then
        echo -e "${RED}[!] Weak TLS/SSL Cipher Suites:${NC}"
        echo "$WEAK_CIPHERS" | awk '{print " - " $1}' | sort -u
        VULN_FOUND=true
    fi
    # Heartbleed / ROBOT / CCS
    echo "$SSLYZE_OUTPUT" | grep -q "VULNERABLE" && echo -e "${RED}[!] Vulnerabilities detected in SSL/TLS configuration (Heartbleed/ROBOT/CCS)${NC}" && VULN_FOUND=true

    [ "$VULN_FOUND" = false ] && echo -e "${GREEN}[+] No weak TLS versions, weak ciphers, or critical vulnerabilities detected${NC}"

done

# ------------ End -------------
echo
echo "================================================="
echo -e "${GREEN}WEB + SSL/TLS SCANS COMPLETED SUCCESSFULLY${NC}"
echo "================================================="
