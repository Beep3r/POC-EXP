# CVE-2018-1000006-DEMO
The Demo for CVE-2018-1000006

# Analysis
[Electron < v1.8.2-beta.4 远程命令执行漏洞—【CVE-2018-1000006】](https://xianzhi.aliyun.com/forum/topic/1990)

# POC
可以直接使用 elec_rce\elec_rce-win32-x64\elec_rce.exe

也可以自己打包成exe应用,生成有漏洞的版本应用，以版本1.7.8为例：
```
electron-packager ./test elec_rce --win --out ./elec_rce --arch=x64 --version=0.0.1 --electron-version=1.7.8 --download.mirror=https://npm.taobao.org/mirrors/electron/
```

![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180124/3.jpg?raw=true)


