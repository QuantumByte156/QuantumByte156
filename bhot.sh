#!/bin/bash

# ==============================================================================
# 网络安全工具智能管理系统 v5.0 (优化增强版)
# 功能：批量管理安全工具，智能依赖解析，并行任务调度，全流程断点续传
# ==============================================================================

# ----------------------
# 环境初始化与配置
# ----------------------
set -euo pipefail  # 严格模式

# 颜色与样式定义（带ANSI转义序列）
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'   # 重置样式
BOLD='\033[1m'
UNDERLINE='\033[4m'

# 全局配置（动态自适应）
WORK_DIR=$(pwd)
LOG_FILE="$WORK_DIR/security_tools.log"
CONFIG_FILE="$WORK_DIR/tool_config.json"
STATE_FILE="$WORK_DIR/execution_state.json"
RETRY_TIMES=3
DELAY_SECONDS=3
MAX_PARALLEL=$(nproc 2>/dev/null || echo 4)  # 自动获取CPU核心数
GOPATH="$WORK_DIR/go"
SUDO_PASSWORD=""
FORCE_SUDO=false
DNS_BACKUP="/etc/resolv.conf.bak"
LAST_FAILED_TOOL=""
TOOL_CACHE="$WORK_DIR/cache"  # 新增缓存目录

# 错误类型定义（带错误码）
ERROR_FATAL=1
ERROR_RECOVERABLE=2
ERROR_WARNING=3
ERROR_INPUT=4

# ----------------------
# 工具仓库元数据（结构化定义）
# 格式: [工具名]="克隆命令 目录名 分类 语言 启用 依赖类型 构建文件 备注"
# 新增工具支持（共120+款）
declare -A tools
tools[txtool]="git clone https://github.com/kuburan/txtool.git txtool 信息收集 Python true python requirements.txt 轻量级信息收集工具"
tools[Sublist3r]="git clone https://github.com/aboul3la/Sublist3r.git Sublist3r 子域名枚举 Python true python requirements.txt 子域名枚举工具"
tools[OneForAll]="git clone https://github.com/shmilylty/OneForAll.git OneForAll 子域名枚举 Python true python requirements.txt 全能子域名收集工具"
tools[Amass]="git clone https://github.com/OWASP/Amass.git Amass 信息收集 Go true go go.mod OWASP官方信息收集工具"
tools[masscan]="git clone https://github.com/robertdavidgraham/masscan.git masscan 端口扫描 C true c Makefile 高速端口扫描器"
tools[nmap]="git clone https://github.com/nmap/nmap.git nmap 端口扫描 C true c configure 经典端口扫描工具"
tools[Sn1per]="git clone https://github.com/1n3/Sn1per.git Sn1per 渗透测试 Mixed true mixed requirements.txt 自动化渗透测试框架"
tools[Osmedeus]="git clone https://github.com/j3ssie/Osmedeus.git Osmedeus 渗透测试 Go true go go.mod 一体化渗透测试平台"
tools[shodan-python]="git clone https://github.com/achillean/shodan-python.git shodan-python 网络空间测绘 Python true python requirements.txt Shodan官方API客户端"
tools[subfinder]="git clone https://github.com/projectdiscovery/subfinder.git subfinder 子域名枚举 Go true go go.mod 高性能子域名发现工具"
tools[thc-hydra]="git clone https://github.com/vanhauser-thc/thc-hydra.git thc-hydra 密码爆破 C true c Makefile 经典密码爆破工具"
tools[metasploit-framework]="git clone https://github.com/rapid7/metasploit-framework.git metasploit-framework 漏洞利用 Ruby true ruby Gemfile 漏洞利用框架"
tools[sqlmap]="git clone https://github.com/sqlmapproject/sqlmap.git sqlmap 漏洞检测 Python true python requirements.txt SQL注入检测工具"
tools[gowitness]="git clone https://github.com/sensepost/gowitness.git gowitness 服务截图 Go true go go.mod 网站截图工具"
tools[assetfinder]="git clone https://github.com/tomnomnom/assetfinder.git assetfinder 资产发现 Go true go go.mod 资产发现工具"
tools[ipscan]="git clone https://github.com/angryip/ipscan.git ipscan 端口扫描 Java true java pom.xml 轻量级端口扫描器"
tools[fofa_viewer]="git clone https://github.com/wgpsec/fofa_viewer.git fofa_viewer 网络空间测绘 Python true python requirements.txt FOFA数据可视化工具"
tools[ENScan_GO]="git clone https://github.com/wgpsec/ENScan_GO.git ENScan_GO 漏洞扫描 Go true go go.mod 企业级漏洞扫描器"
tools[ThunderSearch]="git clone https://github.com/xzajyjs/ThunderSearch.git ThunderSearch 网络空间测绘 Python true python requirements.txt 快速网络空间搜索工具"
tools[fofax]="git clone https://github.com/xiecat/fofax.git fofax 网络空间测绘 Python true python requirements.txt FOFA命令行工具"
tools[ksubdomain]="git clone https://github.com/knownsec/ksubdomain.git ksubdomain 子域名枚举 Go true go go.mod 高效子域名枚举工具"
tools[EyeWitness]="git clone https://github.com/RedSiege/EyeWitness.git EyeWitness 服务截图 Python true python requirements.txt 服务识别与截图工具"
tools[ICS-Security-Toolkit]="git clone https://github.com/SECFORCE/ICS-Security-Toolkit.git ICS-Security-Toolkit 工业控制安全 Python true python requirements.txt 工控安全工具集"
tools[tide]="git clone https://github.com/JuiceShop/tide.git tide 漏洞扫描 NodeJS true node package.json 语义化漏洞扫描器"
tools[evilginx2]="git clone https://github.com/kgretzky/evilginx2.git evilginx2 钓鱼攻击 Go true go go.mod 高级钓鱼工具"
tools[Covenant]="git clone https://github.com/cobbr/Covenant.git Covenant 后渗透 .NET true dotnet project.json 后渗透框架"
tools[kxss]="git clone https://github.com/Emoe/kxss.git kxss XSS检测 Python true python requirements.txt XSS漏洞检测工具"
tools[wpscan]="git clone https://github.com/wpscanteam/wpscan.git wpscan CMS漏洞检测 Ruby true ruby Gemfile WordPress漏洞扫描"
tools[retire.js]="git clone https://github.com/RetireJS/retire.js.git retire.js 前端安全 NodeJS true node package.json JavaScript安全检测"
tools[safety]="git clone https://github.com/pyupio/safety.git safety Python安全 Python true python setup.py Python依赖安全检测"
tools[PayloadsAllTheThings]="git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git PayloadsAllTheThings 漏洞Payload 文档 true mixed README.md 漏洞Payload集合"
tools[XSStrike]="git clone https://github.com/s0md3v/XSStrike.git XSStrike XSS检测 Python true python requirements.txt 高级XSS检测工具"
tools[wfuzz]="git clone https://github.com/xmendez/wfuzz.git wfuzz 模糊测试 Python true python setup.py Web模糊测试工具"
tools[w3af]="git clone https://github.com/andresriancho/w3af.git w3af 漏洞扫描 Python true python requirements.txt Web漏洞扫描框架"
tools[nikto]="git clone https://github.com/sullo/nikto.git nikto 漏洞扫描 Perl true perl Makefile Web服务器漏洞扫描"
tools[skipfish]="git clone https://github.com/google/skipfish.git skipfish 漏洞扫描 C true c Makefile 主动Web安全侦察工具"
tools[xray]="git clone https://github.com/chaitin/xray.git xray 漏洞扫描 Go true go go.mod 高效漏洞扫描器"
tools[nuclei]="git clone https://github.com/projectdiscovery/nuclei.git nuclei 漏洞扫描 Go true go go.mod 模板化漏洞扫描工具"
tools[pocsuite3]="git clone https://github.com/knownsec/pocsuite3.git pocsuite3 漏洞利用 Python true python requirements.txt POC框架"
tools[scan4all]="git clone https://github.com/GhostTroops/scan4all.git scan4all 综合扫描 Python true python requirements.txt 一体化扫描工具"
tools[afrog]="git clone https://github.com/zan8in/afrog.git afrog 漏洞扫描 Go true go go.mod 快速漏洞扫描器"
tools[vulmap]="git clone https://github.com/zhzyker/vulmap.git vulmap 漏洞利用 Go true go go.mod 漏洞利用工具"
tools[kscan]="git clone https://github.com/lcvvvv/kscan.git kscan 端口扫描 Go true go go.mod 高速端口扫描工具"
tools[wapiti]="git clone https://github.com/wapiti-scanner/wapiti.git wapiti 漏洞扫描 Python true python setup.py Web漏洞扫描器"
tools[dirsearch]="git clone https://github.com/maurosoria/dirsearch.git dirsearch 目录扫描 Python true python requirements.txt 目录爆破工具"
tools[Gf-Patterns]="git clone https://github.com/1ndianl33t/Gf-Patterns.git Gf-Patterns 正则表达式 文档 true mixed README.md 渗透测试正则表达式"
tools[JSQLInjection]="git clone https://github.com/BeichenDream/JSQLInjection.git JSQLInjection SQL注入 Java true java pom.xml Java版SQL注入工具"
tools[Gopherus]="git clone https://github.com/tarunkant/Gopherus.git Gopherus 漏洞利用 Python true python requirements.txt GopherPayload生成工具"
tools[jwt_tool]="git clone https://github.com/ticarpi/jwt_tool.git jwt_tool JWT攻击 Go true go go.mod JWT漏洞利用工具"
tools[APIScan-CLI]="git clone https://github.com/APIScanIO/APIScan-CLI.git APIScan-CLI API安全 Go true go go.mod API安全检测工具"
tools[serverless-scanner]="git clone https://github.com/bridgecrewio/serverless-scanner.git serverless-scanner 云安全 NodeJS true node package.json Serverless安全检测"
tools[Empire]="git clone https://github.com/BC-SECURITY/Empire.git Empire 后渗透 Python true python requirements.txt 后渗透框架"
tools[AutoSploit]="git clone https://github.com/NullArray/AutoSploit.git AutoSploit 自动化渗透 Python true python requirements.txt 自动化渗透工具"
tools[exploit-database]="git clone https://github.com/offensive-security/exploit-database.git exploit-database 漏洞库 文档 true mixed README.md 漏洞数据库"
tools[POC-bomber]="git clone https://github.com/tr0uble-mAker/POC-bomber.git POC-bomber 漏洞利用 Python true python requirements.txt POC批量验证工具"
tools[railgun]="git clone https://github.com/lz520520/railgun.git railgun 漏洞利用 Python true python requirements.txt 漏洞利用框架"
tools[yakit]="git clone https://github.com/yaklang/yakit.git yakit 综合工具 Go true go go.mod 一体化安全工具"
tools[kubesploit]="git clone https://github.com/ekultek/kubesploit.git kubesploit 容器安全 Go true go go.mod 容器漏洞利用工具"
tools[cloudsploit]="git clone https://github.com/aquasecurity/cloudsploit.git cloudsploit 云安全 NodeJS true node package.json 云安全检测工具"
tools[beef]="git clone https://github.com/beefproject/beef.git beef XSS框架 Ruby true ruby Gemfile XSS攻击框架"
tools[slither]="git clone https://github.com/crytic/slither.git slither 智能合约审计 Python true python requirements.txt 智能合约审计工具"
tools[mythx-cli]="git clone https://github.com/mythx/mythx-cli.git mythx-cli 智能合约审计 Go true go go.mod 智能合约安全分析"
tools[uboot-security-check]="git clone https://github.com/intel/uboot-security-check.git uboot-security-check 固件安全 Python true python requirements.txt 固件安全检测"
tools[SharpHound]="git clone https://github.com/BloodHoundAD/SharpHound.git SharpHound 域渗透 C# true csharp project.json 域渗透信息收集"
tools[john]="git clone https://github.com/openwall/john.git john 密码破解 C true c Makefile 密码破解工具"
tools[mimikatz]="git clone https://github.com/gentilkiwi/mimikatz.git mimikatz 密码获取 C true c Makefile Windows密码获取"
tools[monkey]="git clone https://github.com/guardicore/monkey.git monkey 横向移动 Python true python requirements.txt 网络渗透测试工具"
tools[PST-Bucket]="git clone https://github.com/arch3rPro/PST-Bucket.git PST-Bucket 云存储渗透 Python true python requirements.txt S3存储桶渗透工具"
tools[hashcat]="git clone https://github.com/hashcat/hashcat.git hashcat 密码破解 C true c Makefile 高级密码破解工具"
tools[sliver]="git clone https://github.com/BishopFox/sliver.git sliver C2框架 Go true go go.mod 现代C2框架"
tools[Rubeus]="git clone https://github.com/GhostPack/Rubeus.git Rubeus 域渗透 C# true csharp project.json 域渗透工具"
tools[secure-element-audit]="git clone https://github.com/SE-Trust/secure-element-audit.git secure-element-audit 硬件安全 C true c Makefile 安全芯片审计工具"
tools[iseek]="git clone https://github.com/ios-sec/iseek.git iseek iOS安全 Python true python requirements.txt iOS安全检测工具"
tools[wireshark]="git clone https://github.com/wireshark/wireshark.git wireshark 网络分析 C true c Makefile 网络协议分析工具"
tools[burp-suite]="git clone https://github.com/PortSwigger/burp-suite.git burp-suite 网络分析 Java true java pom.xml Web安全测试工具"
tools[zaproxy]="git clone https://github.com/zaproxy/zaproxy.git zaproxy 网络分析 Java true java pom.xml 开源Web安全工具"
tools[bettercap]="git clone https://github.com/bettercap/bettercap.git bettercap 网络嗅探 Go true go go.mod 网络安全瑞士军刀"
tools[mitmproxy]="git clone https://github.com/mitmproxy/mitmproxy.git mitmproxy 网络嗅探 Python true python requirements.txt 中间人代理工具"
tools[ettercap]="git clone https://github.com/Ettercap/ettercap.git ettercap 网络嗅探 C true c Makefile 网络嗅探与MITM攻击"
tools[tcpdump]="git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump 网络分析 C true c Makefile 命令行抓包工具"
tools[scapy]="git clone https://github.com/secdev/scapy.git scapy 网络分析 Python true python setup.py Python网络包处理"
tools[Ladon]="git clone https://github.com/3gstudent/Ladon.git Ladon 内网渗透 C# true csharp project.json 内网渗透工具"
tools[Mobile-Security-Framework-MobSF]="git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git Mobile-Security-Framework-MobSF 移动安全 Python true python requirements.txt 移动应用安全框架"
tools[frida]="git clone https://github.com/frida/frida.git frida 移动安全 C true c Makefile 动态代码插桩工具"
tools[trivy]="git clone https://github.com/aquasecurity/trivy.git trivy 容器安全 Go true go go.mod 容器漏洞扫描器"
tools[checkov]="git clone https://github.com/bridgecrewio/checkov.git checkov 基础设施即代码安全 Python true python requirements.txt IaC安全检测"
tools[clair]="git clone https://github.com/quay/clair.git clair 容器安全 Go true go go.mod 容器镜像漏洞扫描"
tools[kube-hunter]="git clone https://github.com/aquasecurity/kube-hunter.git kube-hunter 容器安全 Go true go go.mod Kubernetes安全检测"
tools[drozer]="git clone https://github.com/ReversecLabs/drozer.git drozer 移动安全 Python true python requirements.txt 移动设备安全测试"
tools[syft]="git clone https://github.com/anchore/syft.git syft 容器安全 Go true go go.mod 软件成分分析工具"
tools[tern]="git clone https://github.com/tern-tools/tern.git tern 容器安全 NodeJS true node package.json 容器镜像分析"
tools[kube-bench]="git clone https://github.com/aquasecurity/kube-bench.git kube-bench 容器安全 Go true go go.mod Kubernetes安全基准"
tools[trivy-operator]="git clone https://github.com/trivy-operator/trivy-operator.git trivy-operator 容器安全 Go true go go.mod Trivy Kubernetes Operator"
tools[Modbus-Scanner]="git clone https://github.com/payatu/Modbus-Scanner.git Modbus-Scanner 工业控制安全 Python true python requirements.txt Modbus协议安全扫描"
tools[fat]="git clone https://github.com/fkie-cad/fat.git fat 工业控制安全 Python true python requirements.txt 工业协议分析工具"
tools[DependencyCheck]="git clone https://github.com/jeremylong/DependencyCheck.git DependencyCheck 依赖安全 Java true java pom.xml 依赖组件安全检测"
tools[bandit]="git clone https://github.com/PyCQA/bandit.git bandit Python安全 Python true python setup.py Python代码安全检测"
tools[flawfinder]="git clone https://github.com/david-a-wheeler/flawfinder.git flawfinder 代码审计 Python true python setup.py 代码安全审计工具"
tools[semgrep]="git clone https://github.com/semgrep/semgrep.git semgrep 代码审计 Python true python setup.py 静态代码分析工具"
tools[sonarqube]="git clone https://github.com/SonarSource/sonarqube.git sonarqube 代码审计 Java true java pom.xml 代码质量管理平台"
tools[codeql]="git clone https://github.com/github/codeql.git codeql 代码审计 C++ true cpp Makefile 代码安全分析引擎"
tools[IoTSecCheck]="git clone https://github.com/yds0926/IoTSecCheck.git IoTSecCheck IoT安全 Python true python requirements.txt IoT设备安全检测"
tools[IOT-Sec-Framework]="git clone https://github.com/UNV-SEC/IOT-Sec-Framework.git IOT-Sec-Framework IoT安全 Python true python requirements.txt IoT安全框架"
tools[AutoRecon]="git clone https://github.com/Tib3rius/AutoRecon.git AutoRecon 自动化渗透 Python true python requirements.txt 自动化侦察工具"
tools[zmap]="git clone https://github.com/zmap/zmap.git zmap 端口扫描 C true c Makefile 高性能端口扫描器"
tools[SecLists]="git clone https://github.com/danielmiessler/SecLists.git SecLists 字典库 文档 true mixed README.md 安全测试字典集合"
tools[Goby]="git clone https://github.com/gobysec/Goby.git Goby 综合工具 Go true go go.mod 一体化网络安全工具"
tools[openvas-smb]="git clone https://github.com/greenbone/openvas-smb.git openvas-smb 漏洞扫描 C true c Makefile OpenVAS SMB模块"
tools[screwdriver]="git clone https://github.com/screwdriver-cd/screwdriver.git screwdriver CI安全 NodeJS true node package.json CI/CD安全平台"
tools[AISEC]="git clone https://github.com/AISEC-io/AISEC.git AISEC AI安全 Python true python requirements.txt AI安全检测工具"
tools[AutoPen]="git clone https://github.com/EntySec/AutoPen.git AutoPen 自动化渗透 Python true python requirements.txt 自动化渗透测试工具"
tools[kunai]="git clone https://github.com/kunai-project/kunai.git kunai 移动安全 Python true python requirements.txt 移动应用安全分析"
tools[baddns]="git clone https://github.com/blacklanternsecurity/baddns.git baddns 网络攻击 Go true go go.mod 恶意DNS工具"
tools[orbit]="git clone https://github.com/orbitscanner/orbit.git orbit 漏洞扫描 Go true go go.mod 分布式漏洞扫描器"
tools[misconfig-mapper]="git clone https://github.com/intigriti/misconfig-mapper.git misconfig-mapper 配置审计 Python true python requirements.txt 配置错误映射工具"
tools[beelzebub]="git clone https://github.com/mariocandela/beelzebub.git beelzebub 漏洞扫描 Python true python requirements.txt 分布式漏洞扫描器"
tools[OpenSCA-cli]="git clone https://github.com/XmirrorSecurity/OpenSCA-cli.git OpenSCA-cli 供应链安全 Go true go go.mod 开源组件安全分析"
tools[medusa]="git clone https://github.com/jmk-foofus/medusa.git medusa 密码爆破 C true c Makefile 并行登录爆破工具"
tools[aircrack-ng]="git clone https://github.com/aircrack-ng/aircrack-ng.git aircrack-ng 无线安全 C true c Makefile 无线密码破解工具"
tools[crunch]="git clone https://github.com/crunchsec/crunch.git crunch 密码生成 C true c Makefile 密码字典生成工具"
tools[osv-scanner]="git clone https://github.com/google/osv-scanner.git osv-scanner 漏洞扫描 Go true go go.mod 开源漏洞扫描器"
tools[theHarvester]="git clone https://github.com/laramies/theHarvester.git theHarvester 信息收集 Python true python requirements.txt 开源信息收集工具"
tools[nuclei-templates]="git clone https://github.com/projectdiscovery/nuclei-templates.git nuclei-templates 漏洞模板 文档 true mixed README.md nuclei漏洞模板库"
tools[Infoga]="git clone https://github.com/m4ll0k/Infoga.git Infoga 信息收集 Python true python requirements.txt 邮箱信息收集工具"
tools[reconspider]="git clone https://github.com/bhavsec/reconspider.git reconspider 信息收集 Python true python requirements.txt 自动化侦察框架"
tools[findomain]="git clone https://github.com/Edu4rdSHL/findomain.git findomain 子域名枚举 Go true go go.mod 快速子域名查找工具"
tools[Photon]="git clone https://github.com/s0md3v/Photon.git Photon 资产发现 Python true python requirements.txt 快速URL收集工具"
tools[kismet]="git clone https://github.com/kismetwireless/kismet.git kismet 无线安全 C++ true cpp Makefile 无线数据包捕获工具"
tools[ethereum-etl]="git clone https://github.com/blockchain-etl/ethereum-etl.git ethereum-etl 区块链安全 Python true python requirements.txt 以太坊数据提取工具"
tools[DDoS-Ripper]="git clone https://github.com/palahsu/DDoS-Ripper.git DDoS-Ripper DDoS攻击 Python true python requirements.txt DDoS攻击检测工具"
tools[slowloris]="git clone https://github.com/gkbrk/slowloris.git slowloris DDoS攻击 Python true python requirements.txt HTTP DoS攻击工具"
tools[ARL-]="git clone https://github.com/AmbroseCdMeng/ARL-.git ARL- 资产测绘 Python true python requirements.txt 资产侦察灯塔"
tools[GoldenEye]="git clone https://github.com/jseidl/GoldenEye.git GoldenEye DDoS攻击 Python true python requirements.txt HTTP洪水攻击工具"
tools[pentmenu]="git clone https://github.com/AeolusTF/pentmenu.git pentmenu 工具集合 Shell true shell setup.sh 渗透测试菜单工具"
tools[recon-ng]="git clone https://github.com/lanmaster53/recon-ng.git recon-ng 信息收集 Python true python requirements.txt Web侦察框架"
tools[subjack]="git clone https://github.com/haccer/subjack.git subjack 子域名接管 Go true go go.mod 子域名接管检测工具"
tools[gau]="git clone https://github.com/lc/gau.git gau URL收集 Go true go go.mod 快速URL提取工具"
tools[ffuf]="git clone https://github.com/ffuf/ffuf.git ffuf 模糊测试 Go true go go.mod 快速Web模糊测试工具"
tools[altdns]="git clone https://github.com/infosec-au/altdns.git altdns 子域名生成 Python true python requirements.txt 子域名变异工具"
tools[dex2jar]="git clone https://github.com/pxb1988/dex2jar.git dex2jar 逆向工程 Java true java pom.xml Android逆向工具"
tools[jadx]="git clone https://github.com/skylot/jadx.git jadx 逆向工程 Java true java pom.xml Android反编译工具"
tools[Ehoney]="git clone https://github.com/seccome/Ehoney.git Ehoney 蜜罐 Python true python requirements.txt 轻量级蜜罐系统"
tools[CuiRi]="git clone https://github.com/NyDubh3/CuiRi.git CuiRi 信息收集 Python true python requirements.txt 资产信息收集工具"

# ----------------------
# 日志系统（结构化日志输出）
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

# 增强型错误处理（带错误上下文跟踪）
handle_error() {
    local error_type=$1; shift
    local error_msg=$1; shift
    local error_detail=$1; shift
    local action=$1; shift
    local context=$1; shift
    
    log "ERR" "错误类型: $error_type | 信息: $error_msg | 上下文: $context"
    log "ERR" "详细信息: $error_detail"
    
    case $error_type in
        "网络错误")
            log "WARN" "检测到网络相关错误，可能是临时问题 (建议检查网络连接)"
            ;;
        "权限错误")
            log "WARN" "检测到权限不足，请确保有sudo权限 (当前用户: $(whoami))"
            ;;
        "依赖错误")
            log "WARN" "检测到依赖缺失，可能需要手动安装相关依赖"
            ;;
        "配置错误")
            log "WARN" "检测到配置问题，请检查配置文件格式"
            ;;
        "输入错误")
            log "WARN" "用户输入无效，请检查输入格式"
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

# ----------------------
# 状态管理（支持断点续传）
# ----------------------
record_execution_state() {
    local current_step=$1
    local last_tool=$2
    
    LAST_FAILED_TOOL=$last_tool
    local state_json=$(cat <<EOF
{
  "current_step": "$current_step",
  "last_tool": "$last_tool",
  "timestamp": "$(date "+%Y-%m-%d %H:%M:%S")"
}
EOF
)
    
    mkdir -p "$(dirname "$STATE_FILE")"
    echo "$state_json" > "$STATE_FILE"
    log "DEBUG" "执行状态已记录: $STATE_FILE"
}

# 恢复执行状态（支持JSON解析错误处理）
restore_execution_state() {
    if [ -f "$STATE_FILE" ]; then
        if ! command -v jq &> /dev/null; then
            log "WARN" "缺少jq工具，无法解析状态文件，将全新执行"
            return 1
        fi
        
        local last_tool=$(jq -r '.last_tool' "$STATE_FILE" 2>/dev/null)
        if [ -n "$last_tool" ]; then
            LAST_FAILED_TOOL=$last_tool
            log "INFO" "检测到上次执行状态，从工具 $LAST_FAILED_TOOL 继续"
            return 0
        else
            log "WARN" "状态文件格式错误，将全新执行"
            return 1
        fi
    fi
    log "INFO" "未检测到执行状态，全新执行"
    return 1
}

# ----------------------
# 安全执行引擎（带命令审计）
# ----------------------
safe_exec() {
    local cmd=$1
    local error_type=$2
    local context=$3
    local log_output=$4  # 是否记录输出
    
    # 命令审计日志
    log "DEBUG" "执行命令: $cmd (错误类型: $error_type, 上下文: $context)"
    
    # 空命令检查
    if [ -z "$cmd" ]; then
        log "ERR" "执行命令为空，跳过 (上下文: $context)"
        return 1
    fi
    
    # 执行命令并捕获输出
    if [ "$log_output" = "true" ]; then
        local output=$($cmd 2>&1)
        local exit_code=$?
        if [ $exit_code -ne 0 ]; then
            log "ERR" "命令执行失败 (退出码: $exit_code): $output"
        fi
    else
        local output=$($cmd 2>/dev/null)
        local exit_code=$?
    fi
    
    # 错误处理
    if [ $exit_code -ne 0 ]; then
        handle_error "$error_type" "命令执行失败" "$output" "retry" "$context"
        return $exit_code
    fi
    
    return 0
}

safe_exec_with_retry() {
    local cmd=$1
    local error_type=$2
    local retry_times=$3
    local delay=$4
    local context=$5
    
    local attempt=0
    while [ $attempt -lt $retry_times ]; do
        safe_exec "$cmd" "$error_type" "$context" "true"
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            return 0  # 执行成功
        fi
        
        attempt=$((attempt+1))
        log "ERR" "命令执行失败 (尝试 $attempt/$retry_times, 延迟 $delay秒): $cmd"
        
        if [ $attempt -lt $retry_times ]; then
            sleep $delay
        else
            handle_error "$error_type" "达到最大重试次数" "命令: $cmd" "continue" "$context"
            return $exit_code
        fi
    done
    
    return 1
}

# ----------------------
# 系统检测与优化
# ----------------------
check_system_dependencies() {
    log "INFO" "开始系统依赖检测..."
    
    # 基础工具检测
    local required_tools=("git" "jq" "make")
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            handle_error "依赖错误" "缺少必要工具" "$tool 未安装，请先安装" "abort" "系统检测"
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
    
    log "SUCC" "系统依赖检测完成"
}

configure_network() {
    log "INFO" "网络配置优化..."
    
    # 代理配置
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
                handle_error "输入错误" "代理地址格式错误" "请输入正确格式的代理地址" "continue" "代理配置"
            fi
        done
    else
        log "INFO" "使用直接连接"
    fi
    
    # DNS优化
    log "INFO" "检测网络连通性..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "INFO" "网络正常，跳过DNS优化"
        return
    fi
    
    log "INFO" "优化DNS解析..."
    if [ -f "/etc/resolv.conf" ]; then
        safe_exec_with_retry "cp /etc/resolv.conf \"$DNS_BACKUP\"" "权限错误" 2 5 "DNS备份"
        log "INFO" "备份DNS到 $DNS_BACKUP"
    fi
    
    safe_exec_with_retry "echo 'nameserver 8.8.8.8' > /etc/resolv.conf" "网络错误" 2 5 "DNS配置"
    safe_exec_with_retry "echo 'nameserver 8.8.4.4' >> /etc/resolv.conf" "网络错误" 2 5 "DNS配置"
    
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "SUCC" "DNS优化成功"
    else
        log "WARN" "DNS优化失败，恢复默认"
        restore_dns
    fi
}

restore_dns() {
    if [ -f "$DNS_BACKUP" ]; then
        safe_exec_with_retry "cp \"$DNS_BACKUP\" /etc/resolv.conf" "权限错误" 2 5 "DNS恢复"
        log "SUCC" "恢复默认DNS"
    else
        log "WARN" "无DNS备份，无法恢复"
    fi
}

# ----------------------
# 依赖管理引擎（按语言分类）
# ----------------------
install_system_dependencies() {
    log "INFO" "安装系统基础依赖..."
    local os=$(uname -s)
    local distro=""
    
    if [ -f /etc/debian_version ]; then
        distro="debian"
        safe_exec_with_retry "apt-get update -y" "网络错误" 3 10 "系统更新"
        safe_exec_with_retry "apt-get install -y git python3 python3-pip make gcc g++ libpcap-dev libssl-dev jq golang-go ruby ruby-dev npm" "依赖错误" 2 5 "系统依赖安装"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        distro="redhat"
        safe_exec_with_retry "yum update -y" "网络错误" 3 10 "系统更新"
        safe_exec_with_retry "yum install -y git python3 python3-pip make gcc-c++ libpcap-devel openssl-devel jq golang ruby ruby-devel npm" "依赖错误" 2 5 "系统依赖安装"
    elif [ -f /etc/arch-release ]; then
        distro="arch"
        safe_exec_with_retry "pacman -Syu --noconfirm" "网络错误" 3 10 "系统更新"
        safe_exec_with_retry "pacman -S --noconfirm git python python-pip make gcc libpcap openssl jq go ruby npm" "依赖错误" 2 5 "系统依赖安装"
    elif [ -f /etc/SuSE-release ]; then
        distro="suse"
        safe_exec_with_retry "zypper refresh" "网络错误" 3 10 "系统更新"
        safe_exec_with_retry "zypper install -y git python3 python3-pip make gcc-c++ libpcap-devel openssl-devel jq golang ruby ruby-devel npm" "依赖错误" 2 5 "系统依赖安装"
    else
        handle_error "配置错误" "未知系统" "无法自动安装依赖，请手动安装" "continue" "系统依赖安装"
        return 1
    fi
    
    log "SUCC" "系统基础依赖安装完成"
    return 0
}

install_python_dependencies() {
    log "INFO" "安装Python开发环境..."
    safe_exec_with_retry "python3 -m pip install --upgrade pip" "依赖错误" 2 5 "Python PIP升级"
    safe_exec_with_retry "python3 -m pip install requests dnspython asyncio aiohttp beautifulsoup4 pyopenssl shodan --no-cache-dir" "依赖错误" 2 5 "Python依赖安装"
    log "SUCC" "Python开发环境安装完成"
}

install_go_dependencies() {
    log "INFO" "安装Go开发环境..."
    if ! command -v go &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y golang-go" "依赖错误" 2 5 "Go安装"
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y golang" "依赖错误" 2 5 "Go安装"
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm go" "依赖错误" 2 5 "Go安装"
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y golang" "依赖错误" 2 5 "Go安装"
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Go，请手动安装" "continue" "Go安装"
            return 1
        fi
    fi
    
    if [ ! -d "$GOPATH" ]; then
        mkdir -p "$GOPATH/src" "$GOPATH/bin" "$GOPATH/pkg"
        echo "export GOPATH=$GOPATH" >> ~/.bashrc
        echo "export PATH=\$GOPATH/bin:\$PATH" >> ~/.bashrc
        source ~/.bashrc
    fi
    
    log "SUCC" "Go开发环境准备完成"
    return 0
}

install_ruby_dependencies() {
    log "INFO" "安装Ruby开发环境..."
    if ! command -v ruby &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y ruby ruby-dev" "依赖错误" 2 5 "Ruby安装"
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y ruby ruby-devel" "依赖错误" 2 5 "Ruby安装"
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm ruby" "依赖错误" 2 5 "Ruby安装"
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y ruby ruby-devel" "依赖错误" 2 5 "Ruby安装"
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Ruby，请手动安装" "continue" "Ruby安装"
            return 1
        fi
    fi
    
    if ! command -v gem &> /dev/null; then
        if [ -f /etc/debian_version ] || [ -f /etc/arch-release ]; then
            safe_exec_with_retry "apt-get install -y rubygems" "依赖错误" 2 5 "RubyGems安装"
        else
            safe_exec_with_retry "yum install -y rubygems" "依赖错误" 2 5 "RubyGems安装"
        fi
    fi
    
    safe_exec_with_retry "gem install bundler --no-document" "依赖错误" 2 5 "Bundler安装"
    log "SUCC" "Ruby开发环境准备完成"
    return 0
}

install_c_dependencies() {
    log "INFO" "安装C/C++开发环境..."
    local os=$(uname -s)
    if [ "$os" = "Linux" ]; then
        if [ -f /etc/debian_version ]; then
            safe_exec_with_retry "apt-get install -y build-essential" "依赖错误" 2 5 "C开发环境安装"
        elif [ -f /etc/redhat-release ]; then
            safe_exec_with_retry "yum install -y gcc make" "依赖错误" 2 5 "C开发环境安装"
        elif [ -f /etc/arch-release ]; then
            safe_exec_with_retry "pacman -S --noconfirm base-devel" "依赖错误" 2 5 "C开发环境安装"
        elif [ -f /etc/SuSE-release ]; then
            safe_exec_with_retry "zypper install -y gcc make" "依赖错误" 2 5 "C开发环境安装"
        fi
    else
        handle_error "配置错误" "非Linux系统" "无法自动安装C开发环境，请手动安装" "continue" "C开发环境安装"
        return 1
    fi
    
    log "SUCC" "C/C++开发环境准备完成"
    return 0
}

install_nodejs_dependencies() {
    log "INFO" "安装NodeJS开发环境..."
    if ! command -v node &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y nodejs npm" "依赖错误" 2 5 "NodeJS安装"
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y nodejs npm" "依赖错误" 2 5 "NodeJS安装"
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm nodejs npm" "依赖错误" 2 5 "NodeJS安装"
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y nodejs npm" "依赖错误" 2 5 "NodeJS安装"
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装NodeJS，请手动安装" "continue" "NodeJS安装"
            return 1
        fi
    fi
    
    log "SUCC" "NodeJS开发环境准备完成"
    return 0
}

install_java_dependencies() {
    log "INFO" "安装Java开发环境..."
    if ! command -v java &> /dev/null || ! command -v javac &> /dev/null; then
        local os=$(uname -s)
        if [ "$os" = "Linux" ]; then
            if [ -f /etc/debian_version ]; then
                safe_exec_with_retry "apt-get install -y default-jdk" "依赖错误" 2 5 "Java安装"
            elif [ -f /etc/redhat-release ]; then
                safe_exec_with_retry "yum install -y java-11-openjdk-devel" "依赖错误" 2 5 "Java安装"
            elif [ -f /etc/arch-release ]; then
                safe_exec_with_retry "pacman -S --noconfirm jdk-openjdk" "依赖错误" 2 5 "Java安装"
            elif [ -f /etc/SuSE-release ]; then
                safe_exec_with_retry "zypper install -y java-11-openjdk-devel" "依赖错误" 2 5 "Java安装"
            fi
        else
            handle_error "配置错误" "非Linux系统" "无法自动安装Java，请手动安装" "continue" "Java安装"
            return 1
        fi
    fi
    
    log "SUCC" "Java开发环境准备完成"
    return 0
}

install_tool_specific_dependencies() {
    log "INFO" "安装工具特定依赖..."
    for tool in "${!tools[@]}"; do
        # 解析工具元数据
        local tool_data=(${tools[$tool]})
        local dir="${tool_data[1]}"
        local dep_type="${tool_data[5]}"
        local build_files="${tool_data[6]}"
        
        # 目录存在性检查
        if [ ! -d "$dir" ]; then
            log "WARN" "工具目录 $dir 不存在，跳过依赖安装 (工具: $tool)"
            continue
        fi
        
        log "INFO" "处理 $tool 依赖..."
        cd "$dir" || { log "ERR" "无法进入目录 $dir (工具: $tool)"; continue; }
        
        case $dep_type in
            "python")
                if [[ $build_files == *"requirements.txt"* ]]; then
                    safe_exec_with_retry "python3 -m pip install -r requirements.txt --upgrade --no-cache-dir" "依赖错误" 2 5 "Python依赖安装 ($tool)"
                fi
                ;;
            "go")
                if [[ $build_files == *"go.mod"* ]]; then
                    safe_exec_with_retry "go mod tidy" "依赖错误" 2 5 "Go依赖安装 ($tool)"
                    safe_exec_with_retry "go build -o bin/$tool ." "依赖错误" 2 5 "Go编译 ($tool)"
                fi
                ;;
            "c")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5 "C编译 ($tool)"
                elif [[ $build_files == *"configure"* ]]; then
                    safe_exec_with_retry "./configure" "依赖错误" 2 5 "C配置 ($tool)"
                    safe_exec_with_retry "make" "依赖错误" 2 5 "C编译 ($tool)"
                    safe_exec_with_retry "sudo make install" "权限错误" 2 5 "C安装 ($tool)"
                fi
                ;;
            "ruby")
                if [[ $build_files == *"Gemfile"* ]]; then
                    safe_exec_with_retry "bundle install" "依赖错误" 2 5 "Ruby依赖安装 ($tool)"
                fi
                ;;
            "node")
                if [[ $build_files == *"package.json"* ]]; then
                    safe_exec_with_retry "npm install" "依赖错误" 2 5 "NodeJS依赖安装 ($tool)"
                fi
                ;;
            "dotnet")
                if [[ $build_files == *"project.json"* ]]; then
                    safe_exec_with_retry "dotnet restore" "依赖错误" 2 5 ".NET依赖安装 ($tool)"
                    safe_exec_with_retry "dotnet build" "依赖错误" 2 5 ".NET编译 ($tool)"
                fi
                ;;
            "csharp")
                if [[ $build_files == *"project.json"* ]]; then
                    safe_exec_with_retry "dotnet restore" "依赖错误" 2 5 "C#依赖安装 ($tool)"
                    safe_exec_with_retry "dotnet build" "依赖错误" 2 5 "C#编译 ($tool)"
                fi
                ;;
            "mixed")
                if [[ $build_files == *"requirements.txt"* ]]; then
                    safe_exec_with_retry "python3 -m pip install -r requirements.txt --upgrade --no-cache-dir" "依赖错误" 2 5 "混合依赖安装 ($tool)"
                fi
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5 "混合依赖安装 ($tool)"
                fi
                if [[ $build_files == *"Gemfile"* ]]; then
                    safe_exec_with_retry "bundle install" "依赖错误" 2 5 "混合依赖安装 ($tool)"
                fi
                ;;
            "shell")
                if [[ $build_files == *"setup.sh"* ]]; then
                    safe_exec_with_retry "chmod +x setup.sh && ./setup.sh" "依赖错误" 2 5 "Shell脚本安装 ($tool)"
                fi
                ;;
            "perl")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5 "Perl编译 ($tool)"
                fi
                ;;
            "cpp")
                if [[ $build_files == *"Makefile"* ]]; then
                    safe_exec_with_retry "make" "依赖错误" 2 5 "C++编译 ($tool)"
                fi
                ;;
            "java")
                if [[ $build_files == *"pom.xml"* ]]; then
                    safe_exec_with_retry "mvn clean install" "依赖错误" 2 5 "Java编译 ($tool)"
                fi
                ;;
        esac
        
        cd "$WORK_DIR" || continue
    done
    log "SUCC" "工具特定依赖安装完成"
}

# ----------------------
# 工具管理引擎（模块化设计）
# ----------------------
initialize_configuration() {
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
    
    # 安全的JSON更新（避免语法错误）
    jq --null-input \
       --arg tool "$tool" \
       --arg status "$status" \
       --arg time "$ts" \
       --arg commit "$commit" \
       --arg file "$CONFIG_FILE" \
       'if type == "object" then . else {} end + {($tool): {"status": $status, "last_updated": $time, "commit": $commit}}' \
       "$CONFIG_FILE" > temp.json && mv temp.json "$CONFIG_FILE"
    record_execution_state "tool_updated" "$tool"
}

process_tool() {
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
            cd "$dir" || { log "ERR" "无法进入目录 $dir (工具: $tool)"; return 1; }
            
            if safe_exec_with_retry "git pull" "网络错误" 3 5 "工具更新 ($tool)"; then
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
            if safe_exec_with_retry "$cmd" "网络错误" 3 5 "工具克隆 ($tool)"; then
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

interactive_tool_selection() {
    log "INFO" "可用工具列表 (共 ${#tools[@]} 款):"
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
    
    # 显示分类选项
    echo -e "  ${YELLOW}c. 按分类筛选${NC}"
    local cat_i=1
    for cat in "${categories[@]}"; do
        echo -e "  ${YELLOW}c$cat_i. $cat${NC}"
        cat_i=$((cat_i+1))
    done
    echo -e "  ${YELLOW}a. 全选${NC}"
    echo -e "  ${YELLOW}q. 退出${NC}\n"
    
    # 显示工具列表
    local tool_i=1
    for tool in "${tools_list[@]}"; do
        # 解析工具元数据
        local tool_data=(${tools[$tool]})
        local cat="${tool_data[2]}"
        echo -e "  ${tool_i}. ${tool:0:15}  ${cat:0:8}"
        tool_i=$((tool_i+1))
    done
    
    local selected=()
    while true; do
        read -p "选择操作 (编号/c分类/a全选/q退出): " choice
        
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
                handle_error "输入错误" "无效分类" "请输入有效分类编号" "continue" "工具选择"
            fi
        elif [[ $choice =~ ^[0-9]+$ ]]; then
            local idx=$((choice-1))
            if [ $idx -lt ${#tools_list[@]} ]; then
                selected=("${tools_list[$idx]}")
                break
            else
                handle_error "输入错误" "无效编号" "请输入有效工具编号" "continue" "工具选择"
            fi
        else
            handle_error "输入错误" "无效输入" "请输入有效操作" "continue" "工具选择"
        fi
    done
    
    log "INFO" "已选择 ${#selected[@]} 个工具"
    echo ""
    return 0
}

parallel_tool_processor() {
    local tools=("$@")
    local total=${#tools[@]}
    local running=0
    local pids=()
    local start_from=0
    
    # 检查断点续传
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
        
        process_tool "$tool" &
        pids+=($!)
        running=$((running+1))
        
        # 并行控制与状态检查
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
    if [ -f "$STATE_FILE" ]; then
        rm "$STATE_FILE"
        log "INFO" "执行状态文件已清理"
    fi
}

#----------------------
# 状态报告生成
#----------------------
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
    
    # 生成HTML报告（新增功能）
    generate_html_report
}

generate_html_report() {
    log "INFO" "生成HTML格式状态报告..."
    local report_file="$WORK_DIR/tool_status_report.html"
    
    cat > "$report_file" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络安全工具状态报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { text-align: center; background-color: #f0f0f0; padding: 10px; }
        .summary { font-weight: bold; margin: 15px 0; }
        .table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .table th { background-color: #f2f2f2; }
        .status-cloned { color: #4CAF50; }
        .status-updated { color: #2196F3; }
        .status-failed { color: #F44336; }
        .status-unknown { color: #9E9E9E; }
.footer{text-align:center；margin-top:30px；color：#666；}
</style>
</head>
<body>
<div class="header">
<h1>网络安全工具状态报告</h1>
<p>生成时间：$(date"+%Y-%m-%d%H：%M：%S")</p>
</div>
    
<div class="summary">
<p>总共：${#tools[@]}个工具，成功：$成功个，失败：$失败个，未知：$未知的个，成功率：$(echo"scale=2；($success*100)/${#tools[@]}"|bc-l)%</p>
</div>
    
<table class="table">
<tr>
<th>序号</th>
<th>工具名称</th>
<th>分类</th>
<th>状态</th>
<th>最后更新时间</th>
<th>提交哈希</th>
</tr>
EOF

当地的我=1
为工具in"${！tools[@]}"; 做
当地的工具数据(_D)=(${tools[$工具]})
当地的猫="${tool_data[2]}"
当地的状态=$(jq-r".$工具.状态" "$CONFIG_FILE"2>/dev/null||"未知")
当地的更新=$(jq-r".$工具.last_updated” "$CONFIG_FILE"2>/dev/null||"从未更新")
local犯罪=$(jq-r".$工具.犯罪" "$CONFIG_FILE"2>/dev/null||"未知")
        
当地的status_class=""
案例$status in
            "已克隆") status_class="状态克隆"; status_text="已克隆" ;;
            "已更新") status_class="状态更新"; status_text="已更新" ;;
            "失败") status_class="状态失败"; status_text="失败" ;;
            *) status_class="状态-未知"; status_text="未知" ;;
ESAC
        
回声"<tr>"
回声"<td>$i</td>"
回声"<td>$工具</td>"
回声"<td>$cat</td>"
回声"<td class=\"$status_class\">$status_text</td>"
回显"<td>$已更新</td>"
回显"<td>$commit</td>"
回显"</tr>"
        
我=$((i+1))
已完成
    
猫>>"$report_file"<<EOF
</table>
    
<div class="页脚">
<p>网络安全工具智能管理系统v5.0生成</p>
<p>报告文件路径：$report_file</p>
</div>
</body>
</html>
EOF
    
日志"suc""HTML报告已生成：$报告文件""suc""HTML报告已生成：$报告文件""suc""HTML报告已生成：$报告文件""suc""HTML报告已生成：$报告文件"
}

#----------------------
#主程序入口
#----------------------
主要的(){
#初始化
>>“$LOG_FILE”
初始化配置(_C)
日志"信息""网络安全工具智能管理系统启动"
日志"信息""工作目录：$work_DIR"
    
#欢迎界面
回声-e"\n${BLUE}===============================================${NC}""\n${BLUE}===============================================${NC}""\n${BLUE}===============================================${NC}""\n${BLUE}===============================================${NC}"
回声-e"${粗体}${下划线}网络安全工具智能管理系统v5.0(优化增强版)${NC}""${粗体}${下划线}网络安全工具智能管理系统v5.0(优化增强版)${NC}""${粗体}${下划线}网络安全工具智能管理系统v5.0(优化增强版)${NC}""${粗体}${下划线}网络安全工具智能管理系统v5.0(优化增强版)${NC}"
回声-E"${BLUE}自动克隆、智能依赖、并行处理、断点续传、HTML报告${NC}""${BLUE}自动克隆、智能依赖、并行处理、断点续传、HTML报告${NC}""${BLUE}自动克隆、智能依赖、并行处理、断点续传、HTML报告${NC}""${BLUE}自动克隆、智能依赖、并行处理、断点续传、HTML报告${NC}"
回声-e"${BLUE}===============================================\n${NC}""${BLUE}===============================================\n${NC}""${BLUE}===============================================\n${NC}""${BLUE}===============================================\n${NC}"
    
#处理命令行参数
如果[$#->0]；则[$#->0]；则
如果["$1"="--retry-failed"]；则["$1"="--retry-failed"]；则
日志"信息""检测到重试失败工具模式"
force_SUDO=正确
其他
日志"警告""未知参数：$1，使用默认模式"
Fi
其他
日志"信息""未传递参数，进入正常工具管理模式"
Fi
    
#系统准备
check_system_dependencies
ask_sudo_password
配置网络(_N)
    
#依赖安装
install_system_dependencies
install_java_dependencies
install_python_dependencies
install_go_dependencies
install_ruby_dependencies
install_c_dependencies
install_nodejs_dependencies
install_tool_specific_dependencies
    
#工具处理
interactive_tool_selection
parallel_tool_processor"${挑选出来的”[@]}“[@]}”"${挑选出来的”[@]}“[@]}”"${挑选出来的”[@]}“[@]}”"${挑选出来的”[@]}“[@]}”
    
#恢复网络配置
restore_dns
    
#生成状态报告
生成状态报告
    
#完成
日志"信息""所有操作完成，详情见$log_FILE"
回声-e"\n${绿色}操作完成！${北卡罗来纳州}工具状态已汇总至日志和超文本标记语言报告""\n${绿色}操作完成！${北卡罗来纳州}工具状态已汇总至日志和超文本标记语言报告""\n${绿色}操作完成！${北卡罗来纳州}工具状态已汇总至日志和超文本标记语言报告""\n${绿色}操作完成！${北卡罗来纳州}工具状态已汇总至日志和超文本标记语言报告"
}

#执行主程序
主“$@”
