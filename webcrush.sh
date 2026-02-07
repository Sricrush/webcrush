```
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
````


#!/bin/bash

# =========================================
# WEB + SSL/TLS SECURITY SCANNER
# Author   : Srinath.K
# Platform : Kali Linux / Linux
# =========================================

# ------------ Colors -------------
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
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
# BANNER
# ==============================
echo -e "${CYAN}"
cat << "EOF"
 __        __   _     ____                _
 \ \      / /__| |__ / ___|_ __ _   _ ___| |__
  \ \ /\ / / _ \ '_ \ |   | '__| | | / __| '_ \
   \ V  V /  __/ |_) | |___| |  | |_| \__ \ | | |
    \_/\_/ \___|_.__/ \____|_|   \__,_|___/_| |_|

EOF
echo -e "${WHITE}Web & SSL Vulnerability Scanner (Kali Linux)"
echo -e "${YELLOW}Author : Srinath.K${NC}\n"

# ------------ Input -------------
DOMAINS=()

if [ "$1" = "-f" ] && [ -f "$2" ]; then
    mapfile -t DOMAINS < "$2"
elif [ $# -ge 1 ]; then
    DOMAINS=("$@")
else
    read -p "Enter the URL(s) (space separated): " INPUT
    DOMAINS=($INPUT)
fi

[ ${#DOMAINS[@]} -eq 0 ] && echo -e "${RED}No domains provided. Exiting.${NC}" && exit 1

# ------------ Domain Loop -------------
for TARGET in "${DOMAINS[@]}"; do
    TARGET_NOPROTO=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||')

    echo -e "\n${CYAN}======================"
    echo "Scanning: $TARGET_NOPROTO"
    echo -e "======================${NC}"

    HEADERS=$(curl -s -I -k "$TARGET")

    # ----------------- Security Headers -----------------
    echo -e "${BLUE}Checking Security Headers${NC}\n"
    MISSING_HEADERS=()

    check_header() {
        echo "$HEADERS" | grep -qi "$1" || MISSING_HEADERS+=("$2")
    }

    check_header "Strict-Transport-Security" "Strict-Transport-Security missing"
    check_header "Content-Security-Policy" "Content-Security-Policy missing"
    check_header "X-Frame-Options" "X-Frame-Options missing"
    check_header "X-Content-Type-Options" "X-Content-Type-Options missing"
    check_header "Referrer-Policy" "Referrer-Policy missing"

    [ ${#MISSING_HEADERS[@]} -eq 5 ] \
        && echo -e "${RED}No security headers present${NC}" \
        || echo -e "${YELLOW}Some security headers present${NC}"

    printf '%s\n' "${MISSING_HEADERS[@]}"

    # ----------------- Server Disclosure -----------------
    echo -e "\n${BLUE}Server Header${NC}"
    echo "$HEADERS" | grep -i "^Server:" \
        && echo -e "${RED}Server header disclosed${NC}" \
        || echo -e "${GREEN}Server header not disclosed${NC}"

    echo -e "\n${BLUE}X-Powered-By Header${NC}"
    echo "$HEADERS" | grep -i "^X-Powered-By:" \
        && echo -e "${RED}X-Powered-By disclosed${NC}" \
        || echo -e "${GREEN}X-Powered-By not disclosed${NC}"
        
   # ----------------- HEADER & OPTION POC -----------------
    echo -e "\n${BLUE}HEADER POC${NC}"
    curl "$TARGET" -I -k
    echo -e "\n${GREEN}Command executed successfully.${NC}"

    echo -e "\n${BLUE}OPTION POC${NC}"
    curl -X OPTIONS "$TARGET" -I -k
    echo -e "\n${GREEN}Command executed successfully.${NC}"

    # ----------------- Cookie Flags -----------------
    echo -e "\n${BLUE}Cookie Flags${NC}"
    COOKIES=$(echo "$HEADERS" | grep -i "Set-Cookie")
    if [ -z "$COOKIES" ]; then
        echo -e "${GREEN}No cookies set${NC}"
    else
        echo "$COOKIES"
        echo "$COOKIES" | grep -qi "secure"   || echo -e "${RED}Missing Secure flag${NC}"
        echo "$COOKIES" | grep -qi "httponly" || echo -e "${RED}Missing HttpOnly flag${NC}"
    fi

    # ----------------- SSL/TLS Scan -----------------
    echo -e "\n${CYAN}Running SSL/TLS Scan (SSLyze)${NC}"

    SSLYZE_OUTPUT=$(PYTHONWARNINGS="ignore" sslyze \
        --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
        --heartbleed --compression --robot --openssl_ccs --reneg --certinfo \
        "$TARGET_NOPROTO:443" 2>/dev/null)

    # ----------------- RAW SSLYZE OUTPUT -----------------
    echo -e "\n${BLUE}--- FULL SSLYZE OUTPUT (RAW) ---${NC}"
    echo "$SSLYZE_OUTPUT"
    echo -e "${BLUE}--- END SSLYZE OUTPUT ---${NC}"

    # ----------------- ANALYSIS -----------------
    VULN_FOUND=false
    echo -e "\n${BLUE}SSL/TLS Analysis Summary${NC}"

    # ---- TLS 1.0 / 1.1 (ONLY IF ENABLED) ----
    for TLS in "TLS 1.0" "TLS 1.1"; do
        if echo "$SSLYZE_OUTPUT" | grep -A12 "$TLS Cipher Suites" | grep -qi "TLS_"; then
            echo -e "${RED}[!] $TLS is ENABLED${NC}"
            VULN_FOUND=true
        fi
    done

    # ---- Weak Cipher Suites with TLS Mapping ----
    echo -e "\n${BLUE}Weak Cipher Suites (TLS Mapping)${NC}"
    WEAK=false

    for TLS in "TLS 1.0" "TLS 1.1" "TLS 1.2" "TLS 1.3"; do
        echo "$SSLYZE_OUTPUT" | grep -A30 "$TLS Cipher Suites" | \
        grep -E "CBC_SHA|3DES_EDE" | \
        awk -v t="$TLS" '{print t " -> " $1}' && WEAK=true
    done

    if [ "$WEAK" = false ]; then
        echo -e "${GREEN}No weak cipher suites detected${NC}"
    else
        VULN_FOUND=true
    fi

    # ---- Critical Vulnerabilities ----
    if echo "$SSLYZE_OUTPUT" | grep -qi "VULNERABLE"; then
        echo -e "\n${RED}[!] Critical SSL/TLS vulnerability detected (Heartbleed / ROBOT / CCS)${NC}"
        VULN_FOUND=true
    fi

    # ---- Final Verdict ----
    [ "$VULN_FOUND" = false ] && \
        echo -e "\n${GREEN}[+] SSL/TLS configuration is secure${NC}"

done

echo -e "\n${GREEN}WEB + SSL/TLS SCANS COMPLETED SUCCESSFULLY${NC}"
