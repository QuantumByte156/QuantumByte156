#!/bin/bash

# ==============================================================================
# 网络安全工具智能管理系统 v4.2
# 功能：批量克隆/更新安全工具，智能依赖管理，增强型错误处理
# ==============================================================================

# ----------------------
# 环境检测与初始化
# ----------------------
set -euo pipefail  # 启用严格模式，遇到错误立即退出

# 颜色定义（带样式控制）
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'  # 恢复默认

# 全局配置（带动态调整）
WORK_DIR=$(pwd)
LOG_FILE="$WORK_DIR/security_tools.log"
CONFIG_FILE="$WORK_DIR/tool_config.json"
RETRY_TIMES=3
DELAY_SECONDS=3
MAX_PARALLEL=$(nproc 2>/dev/null || echo 4)  # 自动获取CPU核心数
GOPATH="$WORK_DIR/go"
SUDO_PASSWORD=""
FORCE_SUDO=false
DNS_BACKUP="/etc/resolv.conf.bak"
LAST_FAILED_TOOL=""  # 记录上次失败的工具
EXECUTION_STATE_FILE="$WORK_DIR/execution_state.json"  # 执行状态文件

# 错误类型定义
ERROR_FATAL=1
ERROR_RECOVERABLE=2
ERROR_WARNING=3

# 工具仓库列表（结构化元数据）
# 格式: [工具名]="克隆命令 目录名 分类 语言 启用 依赖类型 构建文件"
declare -A tools
tools[txtool]="git clone https://github.com/kuburan/txtool.git txtool 信息收集 Python true python requirements.txt"
tools[Sublist3r]="git clone https://github.com/aboul3la/Sublist3r.git Sublist3r 子域名枚举 Python true python requirements.txt"
tools[OneForAll]="git clone https://github.com/shmilylty/OneForAll.git OneForAll 子域名枚举 Python true python requirements.txt"
tools[Amass]="git clone https://github.com/OWASP/Amass.git Amass 信息收集 Go true go go.mod"
tools[masscan]="git clone https://github.com/robertdavidgraham/masscan.git masscan 端口扫描 C true c Makefile"
tools[nmap]="git clone https://github.com/nmap/nmap.git nmap 端口扫描 C true c configure"
tools[Sn1per]="git clone https://github.com/1n3/Sn1per.git Sn1per 渗透测试 Mixed true mixed requirements.txt Makefile"
tools[Osmedeus]="git clone https://github.com/j3ssie/Osmedeus.git Osmedeus 渗透测试 Go true go go.mod"
tools[shodan-python]="git clone https://github.com/achillean/shodan-python.git shodan-python 网络空间测绘 Python true python requirements.txt"
tools[subfinder]="git clone https://github.com/projectdiscovery/subfinder.git subfinder 子域名枚举 Go true go go.mod"
tools[thc-hydra]="git clone https://github.com/vanhauser-thc/thc-hydra.git thc-hydra 密码爆破 C true c Makefile"
tools[metasploit-framework]="git clone https://github.com/rapid7/metasploit-framework.git metasploit-framework 漏洞利用 Ruby true ruby Gemfile"
tools[sqlmap]="git clone https://github.com/sqlmapproject/sqlmap.git sqlmap 漏洞检测 Python true python requirements.txt"
tools[gowitness]="git clone https://github.com/sensepost/gowitness.git gowitness 服务截图 Go true go go.mod"

# ---------------------- 新增工具开始 ----------------------
tools[assetfinder]="git clone https://github.com/tomnomnom/assetfinder.git assetfinder 资产发现 Go true go go.mod"
tools[ipscan]="git clone https://github.com/angryip/ipscan.git ipscan 端口扫描 Java true java pom.xml"
tools[fofa_viewer]="git clone https://github.com/wgpsec/fofa_viewer.git fofa_viewer 网络空间测绘 Python true python requirements.txt"
tools[ENScan_GO]="git clone https://github.com/wgpsec/ENScan_GO.git ENScan_GO 漏洞扫描 Go true go go.mod"
tools[ThunderSearch]="git clone https://github.com/xzajyjs/ThunderSearch.git ThunderSearch 网络空间测绘 Python true python requirements.txt"
tools[fofax]="git clone https://github.com/xiecat/fofax.git fofax 网络空间测绘 Python true python requirements.txt"
tools[ksubdomain]="git clone https://github.com/knownsec/ksubdomain.git ksubdomain 子域名枚举 Go true go go.mod"
tools[EyeWitness]="git clone https://github.com/RedSiege/EyeWitness.git EyeWitness 服务截图 Python true python requirements.txt"
tools[ICS-Security-Toolkit]="git clone https://github.com/SECFORCE/ICS-Security-Toolkit.git ICS-Security-Toolkit 工业控制安全 Python true python requirements.txt"
tools[tide]="git clone https://github.com/JuiceShop/tide.git tide 漏洞扫描 NodeJS true node package.json"
tools[evilginx2]="git clone https://github.com/kgretzky/evilginx2.git evilginx2 钓鱼攻击 Go true go go.mod"
tools[Covenant]="git clone https://github.com/cobbr/Covenant.git Covenant 后渗透 .NET true dotnet project.json"
tools[kxss]="git clone https://github.com/Emoe/kxss.git kxss XSS检测 Python true python requirements.txt"
tools[wpscan]="git clone https://github.com/wpscanteam/wpscan.git wpscan CMS漏洞检测 Ruby true ruby Gemfile"
tools[retire.js]="git clone https://github.com/RetireJS/retire.js.git retire.js 前端安全 NodeJS true node package.json"
tools[safety]="git clone https://github.com/pyupio/safety.git safety Python安全 Python true python setup.py"
tools[PayloadsAllTheThings]="git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git PayloadsAllTheThings 漏洞Payload 文档 true mixed README.md"
tools[XSStrike]="git clone https://github.com/s0md3v/XSStrike.git XSStrike XSS检测 Python true python requirements.txt"
tools[wfuzz]="git clone https://github.com/xmendez/wfuzz.git wfuzz 模糊测试 Python true python setup.py"
tools[w3af]="git clone https://github.com/andresriancho/w3af.git w3af 漏洞扫描 Python true python requirements.txt"
tools[nikto]="git clone https://github.com/sullo/nikto.git nikto 漏洞扫描 Perl true perl Makefile"
tools[skipfish]="git clone https://github.com/google/skipfish.git skipfish 漏洞扫描 C true c Makefile"
tools[xray]="git clone https://github.com/chaitin/xray.git xray 漏洞扫描 Go true go go.mod"
tools[nuclei]="git clone https://github.com/projectdiscovery/nuclei.git nuclei 漏洞扫描 Go true go go.mod"
tools[pocsuite3]="git clone https://github.com/knownsec/pocsuite3.git pocsuite3 漏洞利用 Python true python requirements.txt"
tools[scan4all]="git clone https://github.com/GhostTroops/scan4all.git scan4all 综合扫描 Python true python requirements.txt"
tools[afrog]="git clone https://github.com/zan8in/afrog.git afrog 漏洞扫描 Go true go go.mod"
tools[vulmap]="git clone https://github.com/zhzyker/vulmap.git vulmap 漏洞利用 Go true go go.mod"
tools[kscan]="git clone https://github.com/lcvvvv/kscan.git kscan 端口扫描 Go true go go.mod"
tools[wapiti]="git clone https://github.com/wapiti-scanner/wapiti.git wapiti 漏洞扫描 Python true python setup.py"
tools[dirsearch]="git clone https://github.com/maurosoria/dirsearch.git dirsearch 目录扫描 Python true python requirements.txt"
tools[Gf-Patterns]="git clone https://github.com/1ndianl33t/Gf-Patterns.git Gf-Patterns 正则表达式 文档 true mixed README.md"
tools[JSQLInjection]="git clone https://github.com/BeichenDream/JSQLInjection.git JSQLInjection SQL注入 Java true java pom.xml"
tools[Gopherus]="git clone https://github.com/tarunkant/Gopherus.git Gopherus 漏洞利用 Python true python requirements.txt"
tools[jwt_tool]="git clone https://github.com/ticarpi/jwt_tool.git jwt_tool JWT攻击 Go true go go.mod"
tools[APIScan-CLI]="git clone https://github.com/APIScanIO/APIScan-CLI.git APIScan-CLI API安全 Go true go go.mod"
tools[serverless-scanner]="git clone https://github.com/bridgecrewio/serverless-scanner.git serverless-scanner 云安全 NodeJS true node package.json"
tools[Empire]="git clone https://github.com/BC-SECURITY/Empire.git Empire 后渗透 Python true python requirements.txt"
tools[AutoSploit]="git clone https://github.com/NullArray/AutoSploit.git AutoSploit 自动化渗透 Python true python requirements.txt"
tools[exploit-database]="git clone https://github.com/offensive-security/exploit-database.git exploit-database 漏洞库 文档 true mixed README.md"
tools[POC-bomber]="git clone https://github.com/tr0uble-mAker/POC-bomber.git POC-bomber 漏洞利用 Python true python requirements.txt"
tools[railgun]="git clone https://github.com/lz520520/railgun.git railgun 漏洞利用 Python true python requirements.txt"
tools[yakit]="git clone https://github.com/yaklang/yakit.git yakit 综合工具 Go true go go.mod"
tools[kubesploit]="git clone https://github.com/ekultek/kubesploit.git kubesploit 容器安全 Go true go go.mod"
tools[cloudsploit]="git clone https://github.com/aquasecurity/cloudsploit.git cloudsploit 云安全 NodeJS true node package.json"
tools[beef]="git clone https://github.com/beefproject/beef.git beef XSS框架 Ruby true ruby Gemfile"
tools[slither]="git clone https://github.com/crytic/slither.git slither 智能合约审计 Python true python requirements.txt"
tools[mythx-cli]="git clone https://github.com/mythx/mythx-cli.git mythx-cli 智能合约审计 Go true go go.mod"
tools[uboot-security-check]="git clone https://github.com/intel/uboot-security-check.git uboot-security-check 固件安全 Python true python requirements.txt"
tools[SharpHound]="git clone https://github.com/BloodHoundAD/SharpHound.git SharpHound 域渗透 C# true csharp project.json"
tools[john]="git clone https://github.com/openwall/john.git john 密码破解 C true c Makefile"
tools[mimikatz]="git clone https://github.com/gentilkiwi/mimikatz.git mimikatz 密码获取 C true c Makefile"
tools[monkey]="git clone https://github.com/guardicore/monkey.git monkey 横向移动 Python true python requirements.txt"
tools[PST-Bucket]="git clone https://github.com/arch3rPro/PST-Bucket.git PST-Bucket 云存储渗透 Python true python requirements.txt"
tools[hashcat]="git clone https://github.com/hashcat/hashcat.git hashcat 密码破解 C true c Makefile"
tools[sliver]="git clone https://github.com/BishopFox/sliver.git sliver C2框架 Go true go go.mod"
tools[Rubeus]="git clone https://github.com/GhostPack/Rubeus.git Rubeus 域渗透 C# true csharp project.json"
tools[secure-element-audit]="git clone https://github.com/SE-Trust/secure-element-audit.git secure-element-audit 硬件安全 C true c Makefile"
tools[iseek]="git clone https://github.com/ios-sec/iseek.git iseek iOS安全 Python true python requirements.txt"
tools[wireshark]="git clone https://github.com/wireshark/wireshark.git wireshark 网络分析 C true c Makefile"
tools[burp-suite]="git clone https://github.com/PortSwigger/burp-suite.git burp-suite 网络分析 Java true java pom.xml"
tools[zaproxy]="git clone https://github.com/zaproxy/zaproxy.git zaproxy 网络分析 Java true java pom.xml"
tools[bettercap]="git clone https://github.com/bettercap/bettercap.git bettercap 网络嗅探 Go true go go.mod"
tools[mitmproxy]="git clone https://github.com/mitmproxy/mitmproxy.git mitmproxy 网络嗅探 Python true python requirements.txt"
tools[ettercap]="git clone https://github.com/Ettercap/ettercap.git ettercap 网络嗅探 C true c Makefile"
tools[tcpdump]="git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump 网络分析 C true c Makefile"
tools[scapy]="git clone https://github.com/secdev/scapy.git scapy 网络分析 Python true python setup.py"
tools[Ladon]="git clone https://github.com/3gstudent/Ladon.git Ladon 内网渗透 C# true csharp project.json"
tools[Mobile-Security-Framework-MobSF]="git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git Mobile-Security-Framework-MobSF 移动安全 Python true python requirements.txt"
tools[frida]="git clone https://github.com/frida/frida.git frida 移动安全 C true c Makefile"
tools[trivy]="git clone https://github.com/aquasecurity/trivy.git trivy 容器安全 Go true go go.mod"
tools[checkov]="git clone https://github.com/bridgecrewio/checkov.git checkov 基础设施即代码安全 Python true python requirements.txt"
tools[clair]="git clone https://github.com/quay/clair.git clair 容器安全 Go true go go.mod"
tools[kube-hunter]="git clone https://github.com/aquasecurity/kube-hunter.git kube-hunter 容器安全 Go true go go.mod"
tools[drozer]="git clone https://github.com/ReversecLabs/drozer.git drozer 移动安全 Python true python requirements.txt"
tools[syft]="git clone https://github.com/anchore/syft.git syft 容器安全 Go true go go.mod"
tools[tern]="git clone https://github.com/tern-tools/tern.git tern 容器安全 NodeJS true node package.json"
tools[kube-bench]="git clone https://github.com/aquasecurity/kube-bench.git kube-bench 容器安全 Go true go go.mod"
tools[trivy-operator]="git clone https://github.com/trivy-operator/trivy-operator.git trivy-operator 容器安全 Go true go go.mod"
tools[Modbus-Scanner]="git clone https://github.com/payatu/Modbus-Scanner.git Modbus-Scanner 工业控制安全 Python true python requirements.txt"
tools[fat]="git clone https://github.com/fkie-cad/fat.git fat 工业控制安全 Python true python requirements.txt"
tools[DependencyCheck]="git clone https://github.com/jeremylong/DependencyCheck.git DependencyCheck 依赖安全 Java true java pom.xml"
tools[bandit]="git clone https://github.com/PyCQA/bandit.git bandit Python安全 Python true python setup.py"
tools[flawfinder]="git clone https://github.com/david-a-wheeler/flawfinder.git flawfinder 代码审计 Python true python setup.py"
tools[semgrep]="git clone https://github.com/semgrep/semgrep.git semgrep 代码审计 Python true python setup.py"
tools[sonarqube]="git clone https://github.com/SonarSource/sonarqube.git sonarqube 代码审计 Java true java pom.xml"
tools[codeql]="git clone https://github.com/github/codeql.git codeql 代码审计 C++ true cpp Makefile"
tools[IoTSecCheck]="git clone https://github.com/yds0926/IoTSecCheck.git IoTSecCheck IoT安全 Python true python requirements.txt"
tools[IOT-Sec-Framework]="git clone https://github.com/UNV-SEC/IOT-Sec-Framework.git IOT-Sec-Framework IoT安全 Python true python requirements.txt"
tools[AutoRecon]="git clone https://github.com/Tib3rius/AutoRecon.git AutoRecon 自动化渗透 Python true python requirements.txt"
tools[zmap]="git clone https://github.com/zmap/zmap.git zmap 端口扫描 C true c Makefile"
tools[SecLists]="git clone https://github.com/danielmiessler/SecLists.git SecLists 字典库 文档 true mixed README.md"
tools[Goby]="git clone https://github.com/gobysec/Goby.git Goby 综合工具 Go true go go.mod"
tools[openvas-smb]="git clone https://github.com/greenbone/openvas-smb.git openvas-smb 漏洞扫描 C true c Makefile"
tools[screwdriver]="git clone https://github.com/screwdriver-cd/screwdriver.git screwdriver CI安全 NodeJS true node package.json"
tools[AISEC]="git clone https://github.com/AISEC-io/AISEC.git AISEC AI安全 Python true python requirements.txt"
tools[AutoPen]="git clone https://github.com/EntySec/AutoPen.git AutoPen 自动化渗透 Python true python requirements.txt"
tools[kunai]="git clone https://github.com/kunai-project/kunai.git kunai 移动安全 Python true python requirements.txt"
tools[baddns]="git clone https://github.com/blacklanternsecurity/baddns.git baddns 网络攻击 Go true go go.mod"
tools[orbit]="git clone https://github.com/orbitscanner/orbit.git orbit 漏洞扫描 Go true go go.mod"
tools[misconfig-mapper]="git clone https://github.com/intigriti/misconfig-mapper.git misconfig-mapper 配置审计 Python true python requirements.txt"
tools[beelzebub]="git clone https://github.com/mariocandela/beelzebub.git beelzebub 漏洞扫描 Python true python requirements.txt"
tools[OpenSCA-cli]="git clone https://github.com/XmirrorSecurity/OpenSCA-cli.git OpenSCA-cli 供应链安全 Go true go go.mod"
tools[medusa]="git clone https://github.com/jmk-foofus/medusa.git medusa 密码爆破 C true c Makefile"
tools[aircrack-ng]="git clone https://github.com/aircrack-ng/aircrack-ng.git aircrack-ng 无线安全 C true c Makefile"
tools[crunch]="git clone https://github.com/crunchsec/crunch.git crunch 密码生成 C true c Makefile"
tools[osv-scanner]="git clone https://github.com/google/osv-scanner.git osv-scanner 漏洞扫描 Go true go go.mod"
tools[theHarvester]="git clone https://github.com/laramies/theHarvester.git theHarvester 信息收集 Python true python requirements.txt"
tools[nuclei-templates]="git clone https://github.com/projectdiscovery/nuclei-templates.git nuclei-templates 漏洞模板 文档 true mixed README.md"
tools[Infoga]="git clone https://github.com/m4ll0k/Infoga.git Infoga 信息收集 Python true python requirements.txt"
tools[reconspider]="git clone https://github.com/bhavsec/reconspider.git reconspider 信息收集 Python true python requirements.txt"
tools[findomain]="git clone https://github.com/Edu4rdSHL/findomain.git findomain 子域名枚举 Go true go go.mod"
tools[Photon]="git clone https://github.com/s0md3v/Photon.git Photon 资产发现 Python true python requirements.txt"
tools[kismet]="git clone https://github.com/kismetwireless/kismet.git kismet 无线安全 C++ true cpp Makefile"
tools[ethereum-etl]="git clone https://github.com/blockchain-etl/ethereum-etl.git ethereum-etl 区块链安全 Python true python requirements.txt"
tools[DDoS-Ripper]="git clone https://github.com/palahsu/DDoS-Ripper.git DDoS-Ripper DDoS攻击 Python true python requirements.txt"
tools[slowloris]="git clone https://github.com/gkbrk/slowloris.git slowloris DDoS攻击 Python true python requirements.txt"
tools[ARL-]="git clone https://github.com/AmbroseCdMeng/ARL-.git ARL- 资产测绘 Python true python requirements.txt"
tools[GoldenEye]="git clone https://github.com/jseidl/GoldenEye.git GoldenEye DDoS攻击 Python true python requirements.txt"
tools[pentmenu]="git clone https://github.com/AeolusTF/pentmenu.git pentmenu 工具集合 Shell true shell setup.sh"
tools[recon-ng]="git clone https://github.com/lanmaster53/recon-ng.git recon-ng 信息收集 Python true python requirements.txt"
tools[subjack]="git clone https://github.com/haccer/subjack.git subjack 子域名接管 Go true go go.mod"
tools[gau]="git clone https://github.com/lc/gau.git gau URL收集 Go true go go.mod"
tools[ffuf]="git clone https://github.com/ffuf/ffuf.git ffuf 模糊测试 Go true go go.mod"
tools[altdns]="git clone https://github.com/infosec-au/altdns.git altdns 子域名生成 Python true python requirements.txt"
tools[dex2jar]="git clone https://github.com/pxb1988/dex2jar.git dex2jar 逆向工程 Java true java pom.xml"
tools[jadx]="git clone https://github.com/skylot/jadx.git jadx 逆向工程 Java true java pom.xml"
tools[Ehoney]="git clone https://github.com/seccome/Ehoney.git Ehoney 蜜罐 Python true python requirements.txt"
tools[CuiRi]="git clone https://github.com/NyDubh3/CuiRi.git CuiRi 信息收集 Python true python requirements.txt"
# ---------------------- 新增工具结束 ----------------------

# ----------------------
# 日志与错误处理
# ----------------------
log() {
    local level=$1; shift
    local msg=$1; shift
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    local tid=$(echo $$ | cut -c1-4)
    local log_msg="[$level][T$tid] $ts - $msg"
    
    case $level in
        "INFO") echo -e "[${BLUE}INFO${NC}] $msg" ;;
        "SUCC") echo -e "[${GREEN}SUCCESS${NC}] $msg" ;;
        "WARN") echo -e "[${YELLOW}WARNING${NC}] $msg" ;;
        "ERR") echo -e "[${RED}ERROR${NC}] $msg" ;;
        "PROG") echo -ne "[${MAGENTA}PROGRESS${NC}] $msg" ;;
        "DEBUG") echo -e "[${CYAN}DEBUG${NC}] $msg" ;;
    esac | tee -a "$LOG_FILE"
}

# 错误处理核心函数，支持错误分类和交互式恢复
handle_error() {
    local error_type=$1; shift
    local error_msg=$1; shift
    local error_detail=$1; shift
    local action=$1; shift
    
    log "ERR" "错误类型: $error_type | 信息: $error_msg"
    log "ERR" "详细信息: $error_detail"
    
    case $error_type in
        "网络错误")
            log "WARN" "检测到网络相关错误，可能是临时问题"
            ;;
        "权限错误")
            log "WARN" "检测到权限不足，请检查sudo权限"
            ;;
        "依赖错误")
            log "WARN" "检测到依赖缺失，可能需要手动安装"
            ;;
        "配置错误")
            log "WARN" "检测到配置问题，请检查配置文件"
            ;;
    esac
    
    if [ "$action" = "abort" ]; then
        log "ERR" "致命错误，程序终止"
        exit $ERROR_FATAL
    elif [ "$action" = "retry" ]; then
        log "INFO" "是否重试此操作? (y/n, 默认n): "
        read -r choice
        if [[ $choice =~ ^[yY]$ ]]; then
            return 0  # 允许重试
        else
            log "INFO" "用户选择跳过此错误"
            return 1  # 跳过错误
        fi
    elif [ "$action" = "continue" ]; then
        log "INFO" "继续执行后续操作"
        return 0
    fi
}

# 记录执行状态，支持断点续传
record_execution_state() {
    local current_step=$1
    local last_tool=$2
    
    LAST_FAILED_TOOL=$last_tool
    local state_json="{\"current_step\": \"$current_step\", \"last_tool\": \"$last_tool\"}"
    
    echo "$state_json" > "$EXECUTION_STATE_FILE"
    log "DEBUG" "执行状态已记录: $state_json"
}

# 恢复执行状态
restore_execution_state() {
    if [ -f "$EXECUTION_STATE_FILE" ]; then
        local state=$(cat "$EXECUTION_STATE_FILE")
        LAST_FAILED_TOOL=$(echo "$state" | jq -r ".last_tool" 2>/dev/null)
        log "INFO" "检测到上次执行状态，最后失败工具: $LAST_FAILED_TOOL"
        return 0
    fi
    log "INFO" "未检测到执行状态，全新执行"
    return 1
}

# ----------------------
# 系统交互与安全执行
# ----------------------
ask_sudo_password() {
    if [ -z "$SUDO_PASSWORD" ] && [ "$FORCE_SUDO" = true ]; then
        stty -echo
        read -p "请输入sudo密码: " SUDO_PASSWORD
        stty echo
        echo
    fi
}

# 增强型安全执行，带错误分类和重试
safe_exec_with_retry() {
    local cmd=$1
    local error_type=$2
    local retry_times=$3
    local delay=$4
    
    log "DEBUG" "执行: $cmd (错误类型: $error_type, 重试: $retry_times 次)"
    
    # 新增空命令检查
    if [ -z "$cmd" ]; then
        log "ERR" "执行命令为空，跳过"
        return 1
    fi
    
    local attempt=0
    while [ $attempt -lt $retry_times ]; do
        if [ "$FORCE_SUDO" = true ] && [[ $cmd == sudo* ]]; then
            echo "$SUDO_PASSWORD" | sudo -S $cmd
        else
            eval $cmd
        fi
        
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            return 0  # 执行成功
        fi
        
        # 错误处理
        attempt=$((attempt+1))
        log "ERR" "命令执行失败 (尝试 $attempt/$retry_times): $cmd"
        
        if [ $attempt -lt $retry_times ]; then
            handle_error "$error_type" "命令执行失败，准备重试" "退出码: $exit_code" "retry"
            sleep $delay
        else
            handle_error "$error_type" "命令执行失败，达到最大重试次数" "退出码: $exit_code" "continue"
            return $exit_code
        fi
    done
    
    return 1
}

# ----------------------
# 系统检测与配置
# ----------------------
check_system() {
    log "INFO" "开始系统检测..."
    
    # 基础工具检测
    for cmd in git jq; do
        if ! command -v $cmd &> /dev/null; then
            handle_error "依赖错误" "缺少必要工具" "$cmd 未安装，请先安装" "abort"
        fi
    done
    
    # 磁盘空间检测
    local disk=$(df -BM "$WORK_DIR" | awk 'NR==2 {print $4}' | sed 's/M//')
    if [ $disk -lt 20480 ]; then  # 20GB
        log "WARN" "磁盘空间仅 $disk MB，建议预留至少20GB"
    else
        log "INFO" "可用磁盘空间: $disk MB"
    fi
    
    # CPU核心数检测
    local cores=$(nproc 2>/dev/null || echo 4)
    log "INFO" "检测到 $cores 个CPU核心，设置最大并行数: $cores"
    MAX_PARALLEL=$cores
    
    log "SUCC" "系统检测完成"
}

configure_proxy() {
    read -p "是否配置代理? (y/n, 默认n): " choice
    choice=${choice:-n}
    
    if [[ $choice =~ ^[yY]$ ]]; then
        while true; do
            read -p "输入代理地址 (http://proxy:port): " PROXY_URL
            if [[ $PROXY_URL =~ ^http://[a-zA-Z0-9.:]+$ ]]; then
                export http_proxy=$PROXY_URL https_proxy=$PROXY_URL all_proxy=$PROXY_URL
                log "SUCC" "代理已配置: $PROXY_URL"
                break
            else
                handle_error "配置错误" "代理地址格式错误" "请输入正确格式的代理地址" "continue"
            fi
        done
    else
        log "INFO" "使用直接连接"
    fi
}

optimize_dns() {
    log "INFO" "检测网络连通性..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "INFO" "网络正常，跳过DNS优化"
        return
    fi
    
    log "INFO" "优化DNS解析..."
    if [ -f "/etc/resolv.conf" ]; then
        safe_exec_with_retry "cp /etc/resolv.conf \"$DNS_BACKUP\"" "权限错误" 2 5
        log "INFO" "备份DNS到 $DNS_BACKUP"
    fi
    
    safe_exec_with_retry "echo 'nameserver 8.8.8.8' > /etc/resolv.conf" "网络错误" 2 5
    safe_exec_with_retry "echo 'nameserver 8.8.4.4' >> /etc/resolv.conf" "网络错误" 2 5
    
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "SUCC" "DNS优化成功"
    else
        log "WARN" "DNS优化失败，恢复默认"
        restore_dns
    fi
}

restore_dns() {
    if [ -f "$DNS_BACKUP" ]; then
        safe_exec_with_retry "cp \"$DNS_BACKUP\" /etc/resolv.conf" "权限错误" 2 5
        log "SUCC" "恢复默认DNS"
    else
        log "WARN" "无DNS备份，无法恢复"
    fi
}

# ----------------------
# 依赖管理
# ----------------------
install_system_deps() {
    log "INFO" "安装系统依赖..."
    local os=$(uname -s)
    local distro=""
    
    if [ -f /etc/debian_version ]; then
        distro="debian"
        safe_exec_with_retry "apt-get update -y" "网络错误" 3 10
        safe_exec_with_retry "apt-get install -y git python3 python3-pip make gcc g++ libpcap-dev libssl-dev jq golang-go ruby ruby-dev npm" "依赖错误" 2 5
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        distro="redhat"
        safe_exec_with_retry "yum update -y" "网络错误" 3 10
        safe_exec_with_retry "yum install -y git python3 python3-pip make gcc-c++ libpcap-devel openssl-devel jq golang ruby ruby-devel npm" "依赖错误" 2 5
    elif [ -f /etc/arch-release ]; then
        distro="arch"
        safe_exec_with_retry "pacman -Syu --noconfirm" "网络错误" 3 10
        safe_exec_with_retry "pacman -S --noconfirm git python python-pip make gcc libpcap openssl jq go ruby npm" "依赖错误" 2 5
    elif [ -f /etc/SuSE-release ]; then
        distro="suse"
        safe_exec_with_retry "zypper refresh" "网络错误" 3 10
        safe_exec_with_retry "zypper install -y git python3 python3-pip make gcc-c++ libpcap-devel openssl-devel jq golang ruby ruby-devel npm" "依赖错误" 2 5
    else
        handle_error "配置错误" "未知系统" "无法自动安装依赖，请手动安装" "continue"
        return 1
    fi
    
    log "SUCC" "系统依赖安装完成"
    return 0
}

install_python_deps() {
    log "INFO" "安装Python依赖..."
    safe_exec_with_retry "python3 -m pip install --upgrade pip" "依赖错误" 2 5
    safe_exec_with_retry "python3 -m pip install requests dnspython asyncio aiohttp beautifulsoup4 pyopenssl shodan --no-cache-dir" "依赖错误" 2 5
    log "SUCC" "Python依赖安装完成"
}

install_go_deps() {
    log "INFO" "安装Go环境..."
    if ! command -v go &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y golang-go" "依赖错误" 2 5
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y golang" "依赖错误" 2 5
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm go" "依赖错误" 2 5
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y golang" "依赖错误" 2 5
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Go，请手动安装" "continue"
            return 1
        fi
    fi
    
    if [ ! -d "$GOPATH" ]; then
        mkdir -p "$GOPATH/src" "$GOPATH/bin" "$GOPATH/pkg"
        echo "export GOPATH=$GOPATH" >> ~/.bashrc
        echo "export PATH=\$GOPATH/bin:\$PATH" >> ~/.bashrc
        source ~/.bashrc
    fi
    
    log "SUCC" "Go环境准备完成"
    return 0
}

install_ruby_deps() {
    log "INFO" "安装Ruby环境..."
    if ! command -v ruby &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y ruby ruby-dev" "依赖错误" 2 5
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y ruby ruby-devel" "依赖错误" 2 5
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm ruby" "依赖错误" 2 5
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y ruby ruby-devel" "依赖错误" 2 5
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Ruby，请手动安装" "continue"
            return 1
        fi
    fi
    
    if ! command -v gem &> /dev/null; then
        if [ -f /etc/debian_version ] || [ -f /etc/arch-release ]; then
            safe_exec_with_retry "apt-get install -y rubygems" "依赖错误" 2 5
        else
            safe_exec_with_retry "yum install -y rubygems" "依赖错误" 2 5
        fi
    fi
    
    safe_exec_with_retry "gem install bundler --no-document" "依赖错误" 2 5
    log "SUCC" "Ruby环境准备完成"
    return 0
}

install_c_deps() {
    log "INFO" "安装C编译环境..."
    local os=$(uname -s)
    if [ "$os" = "Linux" ]; then
        if [ -f /etc/debian_version ]; then
            safe_exec_with_retry "apt-get install -y build-essential" "依赖错误" 2 5
        elif [ -f /etc/redhat-release ]; then
            safe_exec_with_retry "yum install -y gcc make" "依赖错误" 2 5
        elif [ -f /etc/arch-release ]; then
            safe_exec_with_retry "pacman -S --noconfirm base-devel" "依赖错误" 2 5
        elif [ -f /etc/SuSE-release ]; then
            safe_exec_with_retry "zypper install -y gcc make" "依赖错误" 2 5
        fi
    else
        handle_error "配置错误" "非Linux系统" "无法自动安装C编译环境，请手动安装" "continue"
        return 1
    fi
    
    log "SUCC" "C编译环境准备完成"
    return 0
}

install_nodejs_deps() {
    log "INFO" "安装NodeJS环境..."
    if ! command -v node &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y nodejs npm" "依赖错误" 2 5
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y nodejs npm" "依赖错误" 2 5
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm nodejs npm" "依赖错误" 2 5
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y nodejs npm" "依赖错误" 2 5
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装NodeJS，请手动安装" "continue"
            return 1
        fi
    fi
    
    log "SUCC" "NodeJS环境准备完成"
    return 0
}

install_java_deps() {
    log "INFO" "安装Java环境..."
    if ! command -v java &> /dev/null || ! command -v javac &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y default-jdk" "依赖错误" 2 5
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y java-11-openjdk-devel" "依赖错误" 2 5
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm jdk-openjdk" "依赖错误" 2 5
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y java-11-openjdk-devel" "依赖错误" 2 5
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Java，请手动安装" "continue"
            return 1
        fi
    fi
    
    log "SUCC" "Java环境准备完成"
    return 0
}

install_tool_deps() {
    log "INFO" "安装工具特定依赖..."
    for tool in "${!tools[@]}"; do
        # 解析工具元数据
        local tool_data=(${tools[$tool]})
        local dir="${tool_data[1]}"
        local dep_type="${tool_data[5]}"
        local build_files="${tool_data[6]}"
        
        # 新增目录存在性检查
        if [ ! -d "$dir" ]; then
            log "WARN" "工具目录 $dir 不存在，跳过依赖安装"
            continue
        fi
        
        log "INFO" "处理 $tool 依赖..."
        cd "$dir" || { log "ERR" "无法进入目录 $dir"; continue; }
        
        case $dep_type in
            "python")
                if [[ $build_files == *"requirements.txt"* ]]; then
                    safe_exec_with_retry "python3 -m pip install -r requirements.txt --upgrade --no-cache-dir" "依赖错误" 2 5
                fi
                ;;
            "go")
                if [[ $build_files == *"go.mod"* ]]; then
                    safe_exec_with_retry "go mod tidy" "依赖错误" 2 5
                    safe_exec_with_retry "go build -o bin/$tool ." "依赖错误" 2 5
                fi
                ;;
            "c")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5
                elif [[ $build_files == *"configure"* ]]; then
                    safe_exec_with_retry "./configure" "依赖错误" 2 5
                    safe_exec_with_retry "make" "依赖错误" 2 5
                    safe_exec_with_retry "sudo make install" "权限错误" 2 5
                fi
                ;;
            "ruby")
                if [[ $build_files == *"Gemfile"* ]]; then
                    safe_exec_with_retry "bundle install" "依赖错误" 2 5
                fi
                ;;
            "node")
                if [[ $build_files == *"package.json"* ]]; then
                    safe_exec_with_retry "npm install" "依赖错误" 2 5
                fi
                ;;
            "dotnet")
                if [[ $build_files == *"project.json"* ]]; then
                    safe_exec_with_retry "dotnet restore" "依赖错误" 2 5
                    safe_exec_with_retry "dotnet build" "依赖错误" 2 5
                fi
                ;;
            "csharp")
                if [[ $build_files == *"project.json"* ]]; then
                    safe_exec_with_retry "dotnet restore" "依赖错误" 2 5
                    safe_exec_with_retry "dotnet build" "依赖错误" 2 5
                fi
                ;;
            "mixed")
                if [[ $build_files == *"requirements.txt"* ]]; then
                    safe_exec_with_retry "python3 -m pip install -r requirements.txt --upgrade --no-cache-dir" "依赖错误" 2 5
                fi
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5
                fi
                if [[ $build_files == *"Gemfile"* ]]; then
                    safe_exec_with_retry "bundle install" "依赖错误" 2 5
                fi
                ;;
            "shell")
                if [[ $build_files == *"setup.sh"* ]]; then
                    safe_exec_with_retry "chmod +x setup.sh && ./setup.sh" "依赖错误" 2 5
                fi
                ;;
            "perl")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5
                fi
                ;;
            "cpp")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5
                fi
                ;;
            "java")
                if [[ $build_files == *"pom.xml"* ]]; then
                    safe_exec_with_retry "mvn clean install" "依赖错误" 2 5
                fi
                ;;
        esac
        
        cd "$WORK_DIR" || continue
    done
    log "SUCC" "工具依赖安装完成"
}

# ----------------------
# 工具管理
# ----------------------
init_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log "INFO" "创建配置文件 $CONFIG_FILE"
        echo "{}" > "$CONFIG_FILE"
    fi
}

update_tool_status() {
    local tool=$1; shift
    local status=$1; shift
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    local commit=$(cd "$WORK_DIR/${tools[$tool]}" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    
    # 修复后的jq命令（正确转义引号）
    jq --arg tool "$tool" --arg status "$status" --arg time "$ts" --arg commit "$commit" \
       ". + {\"$\{tool}\": {\"status\": \"$\{status}\", \"last_updated\": \"$\{time}\", \"commit\": \"$\{commit}\"}}" \
       "$CONFIG_FILE" > temp.json && mv temp.json "$CONFIG_FILE"
    record_execution_state "tool_updated" "$tool"
}

clone_or_update_tool() {
    local tool=$1
    # 解析工具元数据
    local tool_data=(${tools[$tool]})
    local cmd="${tool_data[0]}"
    local dir="${tool_data[1]}"
    local retry=0
    
    while [ $retry -lt $RETRY_TIMES ]; do
        log "PROG" "处理 $tool (尝试 $((retry+1)/$RETRY_TIMES)..."
        
        if [ -d "$dir" ]; then
            log "INFO" "更新 $tool..."
            cd "$dir" || { log "ERR" "无法进入目录 $dir"; return 1; }
            
            if safe_exec_with_retry "git pull" "网络错误" 3 5; then
                update_tool_status "$tool" "updated"
                log "SUCC" "$tool 已更新"
                cd "$WORK_DIR" || return 1;
                return 0
            else
                log "ERR" "$tool 更新失败，重试中..."
                retry=$((retry+1))
                sleep $DELAY_SECONDS
            fi
        else
            log "INFO" "克隆 $tool..."
            if safe_exec_with_retry "$cmd" "网络错误" 3 5; then
                update_tool_status "$tool" "cloned"
                log "SUCC" "$tool 克隆成功"
                return 0
            else
                log "ERR" "$tool 克隆失败，重试中..."
                retry=$((retry+1))
                sleep $DELAY_SECONDS
            fi
        fi
    done
    
    update_tool_status "$tool" "failed"
    log "ERR" "$tool 处理失败，已放弃"
    record_execution_state "tool_failed" "$tool"
    return 1
}

select_tools_interactive() {
    log "INFO" "可用工具列表:"
    local tools_list=()
    local categories=()
    local i=1
    
    for tool in "${!tools[@]}"; do
        # 解析工具元数据
        local tool_data=(${tools[$tool]})
        if [[ "${tool_data[4]}" == "true" ]]; then
            tools_list+=("$tool")
            local cat="${tool_data[2]}"
            if ! [[ " ${categories[*]} " =~ " $cat " ]]; then
                categories+=("$cat")
            fi
        fi
    done
    
    echo -e "  ${YELLOW}c. 按分类筛选${NC}"
    local cat_i=1
    for cat in "${categories[@]}"; do
        echo -e "  ${YELLOW}c$cat_i. $cat${NC}"
        cat_i=$((cat_i+1))
    done
    echo -e "  ${YELLOW}a. 全选${NC}"
    echo -e "  ${YELLOW}q. 退出${NC}\n"
    
    local selected=()
    while true; do
        read -p "选择操作: " choice
        
        if [[ $choice == "q" ]]; then
            log "INFO" "用户取消操作"
            exit 0
        elif [[ $choice == "a" ]]; then
            selected=("${tools_list[@]}")
            break
        elif [[ $choice == c[0-9] ]]; then
            local cat_idx=$(echo $choice | cut -c2-)
            if [ $((cat_idx-1)) -lt ${#categories[@]} ]; then
                local cat="${categories[$((cat_idx-1))]}"
                for tool in "${tools_list[@]}"; do
                    # 解析工具元数据
                    local tool_data=(${tools[$tool]})
                    if [[ "${tool_data[2]}" == "$cat" ]]; then
                        selected+=("$tool")
                    fi
                done
                break
            else
                handle_error "输入错误" "无效分类" "请输入有效分类编号" "continue"
            fi
        elif [[ $choice =~ ^[0-9]+$ ]]; then
            local idx=$((choice-1))
            if [ $idx -lt ${#tools_list[@]} ]; then
                selected=("${tools_list[$idx]}")
                break
            else
                handle_error "输入错误" "无效编号" "请输入有效工具编号" "continue"
            fi
        else
            handle_error "输入错误" "无效输入" "请输入有效操作" "continue"
        fi
    done
    
    log "INFO" "已选择 ${#selected[@]} 个工具: ${selected[*]}"
    echo ""
    return 0
}

parallel_process_tools() {
    local tools=("$@")
    local total=${#tools[@]}
    local running=0
    local pids=()
    local start_from=0
    
    # 检查是否需要从上次失败的工具开始
    if restore_execution_state; then
        for i in "${!tools[@]}"; do
            if [[ "${tools[i]}" == "$LAST_FAILED_TOOL" ]]; then
                start_from=$i
                log "INFO" "从工具 $LAST_FAILED_TOOL 开始继续执行"
                break
            fi
        done
    fi
    
    log "INFO" "开始并行处理 ($MAX_PARALLEL 并行, 共 $total 个工具):"
    for ((i=$start_from; i<$total; i++)); do
        local tool="${tools[i]}"
        log "PROG" "处理工具 $((i+1))/$total: $tool..."
        
        clone_or_update_tool "$tool" &
        pids+=($!)
        running=$((running+1))
        
        # 控制并行数并检查进程存活
        while [ $running -ge $MAX_PARALLEL ]; do
            wait -n 2>/dev/null
            running=$((running-1))
            pids=()
            for pid in "${!pids[@]}"; do
                if kill -0 ${pids[$pid]} 2>/dev/null; then
                    pids+=(${pids[$pid]})
                fi
            done
            running=${#pids[@]}
        done
    done
    
    # 等待所有进程
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    log "SUCC" "所有工具处理完成"
    # 清理执行状态
    if [ -f "$EXECUTION_STATE_FILE" ]; then
        rm "$EXECUTION_STATE_FILE"
        log "INFO" "执行状态文件已清理"
    fi
}

# ----------------------
# 状态检测与报告
# ----------------------
generate_status_report() {
    log "INFO" "生成工具状态报告..."
    local total=${#tools[@]}
    local success=0
    local failed=0
    local unknown=0
    local success_tools=()
    local failed_tools=()
    
    log "INFO" "----------------------------------------"
    log "INFO" "序号  工具名称        状态        最后更新时间"
    log "INFO" "----------------------------------------"
    
    local i=1
    for tool in "${!tools[@]}"; do
        local status=$(jq -r ".$tool.status" "$CONFIG_FILE" 2>/dev/null || "unknown")
        local updated=$(jq -r ".$tool.last_updated" "$CONFIG_FILE" 2>/dev/null || "从未更新")
        
        log "INFO" "$i. ${tool:0:15}  ${status:0:7}  $updated"
        
        if [ "$status" = "cloned" ] || [ "$status" = "updated" ]; then
            success=$((success+1))
            success_tools+=("$tool")
        elif [ "$status" = "failed" ]; then
            failed=$((failed+1))
            failed_tools+=("$tool")
        else
            unknown=$((unknown+1))
        fi
        i=$((i+1))
    done
    
    log "INFO" "----------------------------------------"
    log "INFO" "总结: 成功 $success, 失败 $failed, 未知 $unknown, 成功率: $(echo "scale=2; ($success*100)/$total" | bc -l)%"
    
    if [ $failed -gt 0 ]; then
        log "WARN" "失败工具列表: ${failed_tools[*]}"
        log "INFO" "建议对失败工具执行: ./security_tools.sh --retry-failed"
    fi
}

# ----------------------
# 主程序流程
# ----------------------
# 初始化
> "$LOG_FILE"
init_config
log "INFO" "网络安全工具智能管理系统启动"
log "INFO" "工作目录: $WORK_DIR"

# 欢迎界面
echo -e "\n${BLUE}===============================================${NC}"
echo -e "${BLUE}  网络安全工具智能管理系统 v4.2               ${NC}"
echo -e "${BLUE}  自动克隆、依赖管理、增强错误处理、断点续传    ${NC}"
echo -e "${BLUE}===============================================\n${NC}"

# 主程序参数处理（修复参数未定义错误）
if [ $# -gt 0 ]; then
    # 检查是否为重试失败工具模式
    if [ "$1" = "--retry-failed" ]; then
        log "INFO" "检测到重试失败工具模式"
        FORCE_SUDO=true
    else
        log "INFO" "正常工具模式启动"
        FORCE_SUDO=false  # 设置默认值
    fi
else
    log "INFO" "未传递参数，进入正常工具模式"
    FORCE_SUDO=false
fi

# 系统准备
check_system
ask_sudo_password
configure_proxy
optimize_dns
    
# 依赖安装
install_system_deps
install_java_deps  # 新增Java依赖安装
install_python_deps
install_go_deps
install_ruby_deps
install_c_deps
install_nodejs_deps
install_tool_deps

# 工具处理
select_tools_interactive
parallel_process_tools "${selected[@]}"

# 恢复DNS
restore_dns

# 生成状态报告
generate_status_report

# 完成
log "INFO" "所有操作完成，详情见 $LOG_FILE"
echo -e "\n${GREEN}操作完成！${NC} 工具状态已汇总至日志文件"
