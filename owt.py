#!/usr/bin/env python
# coding:utf-8
# Build By LandGrey
#
import re
import os
import ssl
import sys
import socket
import requests
import argparse
import HTMLParser
from requests.adapters import HTTPAdapter
from multiprocessing.dummy import Pool as ThreadPool


try:
    requests.packages.urllib3.disable_warnings()
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


def out_format(url, information):
    for char in ('\r', '\n', '\t'):
        information = information.replace(char, "")
    try:
        message = u"{target:50} {information}".format(target=url, information=information.strip())
    except:
        try:
            message = "{target:50} {information}".format(target=url, information=information.strip())
        except:
            message = "{target:50} {information}".format(target=url, information="NoInformation")
    try:
        print(message)
    except UnicodeError:
        print("{target:50} {information}".format(target=url, information="PrintUnicodeError"))


def html_decoder(html_entries):
    try:
        hp = HTMLParser.HTMLParser()
        return hp.unescape(html_entries)
    except Exception as e:
        return html_entries


def match_title(content):
    title = re.findall("document\.title[\s]*=[\s]*['\"](.*?)['\"]", content, re.I | re.M | re.S)
    if title and len(title) >= 1:
        return title[0]
    else:
        title = re.findall("<title.*?>(.*?)</title>", content, re.I | re.M | re.S)
        if title and len(title) >= 1:
            return title[0]
        else:
            return False


def page_decode(url, html_content):
    raw_content = html_content
    try:
        html_content = raw_content.decode("utf-8")
    except UnicodeError:
        try:
            html_content = raw_content.decode("gbk")
        except UnicodeError:
            try:
                html_content = raw_content.decode("gb2312")
            except UnicodeError:
                try:
                    html_content = raw_content.decode("big5")
                except:
                    return out_format(url, "DecodeHtmlError")
    return html_content


def get_title(url):
    origin = url
    if "://" not in url:
        url = "http://" + url.strip()
    url = url.rstrip("/") + "/"
    # First Try Obtain WebSite Title
    try:
        s = requests.Session()
        s.mount('http://', HTTPAdapter(max_retries=1))
        s.mount('https://', HTTPAdapter(max_retries=1))
        req = s.get(url, headers=headers, cookies=cookies,verify=False, allow_redirects=True, timeout=1)
        html_content = req.content
        req.close()
    except requests.ConnectionError:
        return out_format(origin, "ConnectError")
    except requests.Timeout:
        return out_format(origin, "RequestTimeout")
    except socket.timeout:
        return out_format(origin, "SocketTimeout")
    except requests.RequestException:
        return out_format(origin, "RequestException")
    except Exception as e:
        return out_format(origin, "OtherException")
    html_content = page_decode(url, html_content)
    if html_content:
        title = match_title(html_content)
    else:
        exit(0)
    try:
        if title:
            if re.findall("\$#\d{3,};", title):
                title = html_decoder(title)
            return out_format(origin, title)
    except Exception as e:
        return out_format(origin, "FirstTitleError")
    # Find Jump URL
    for pattern in patterns:
        jump = re.findall(pattern, html_content, re.I | re.M)
        if len(jump) == 1:
            if "://" in jump[0]:
                url = jump[0]
            else:
                url += jump[0]
            break
    # Second Try Obtain WebSite Title
    try:
        s = requests.Session()
        s.mount('http://', HTTPAdapter(max_retries=1))
        s.mount('https://', HTTPAdapter(max_retries=1))
        req = s.get(url, headers=headers, cookies=cookies,verify=False, timeout=1)
        html_content = req.content
        req.close()
    except requests.ConnectionError:
        return out_format(origin, "ConnectError")
    except requests.Timeout:
        return out_format(origin, "RequestTimeout")
    except socket.timeout:
        return out_format(origin, "SocketTimeout")
    except requests.RequestException:
        return out_format(origin, "RequestException")
    except Exception as e:
        return out_format(origin, "OtherException")
    html_content = page_decode(url, html_content)
    if html_content:
        title = match_title(html_content)
    else:
        exit(0)
    try:
        if title:
            if re.findall("[$#]\d{3,};", title):
                title = html_decoder(title)
            return out_format(origin, title)
        else:
            return out_format(origin, "NoTitle")
    except Exception as e:
        return out_format(origin, "SecondTitleError")


if __name__ == "__main__":
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    cookies={"thor":"A739E8056545F75D97C738FE0AF8EFF3A3CCB0837C1D270310518E3F4BE1819E3C7519171E632A56660A196019BDDED559575C7A3AA76E2FB681469379C34A1042FADB8AA177BFAFB442173BD4140284618F21A491DC7A64073E3DAB0E6ACB95FE360F5CF8B53A6129DED7D496B735325E82AFC9FCC54B25E450223EB6928A7A87FE5D5A2E0E027892B880C5EAB98A9E","_vender_":"TNK3O6PALVQGHZU3V27M4XHVBRGDCOB3ATSRD4P6WTCVOKIRCMEMKXIPQDFNC3VKAH4AVZ544HYKQLQO5N7IYYDJBU7SCZYP4KC5GMWMQL32LMYIU7FZMO4WNZLFWKI7IRHP5GEL3LULTV25DTXN3COUTGFHGEFM76KJV4GZYZJ47JAHQPWYQAD4WHG7ADP3TBRYIUE2XMMROQNRZ72IZDWGZ4WR623OFJPD3TWY5KEA5Q6YCL47WWAZWJC6TNKJRJSHWYSYDBMSZQDX6LYQVU47JNZMN2KEW2JJ6FACFCBTFZKSRPB224EYBQTYNNHCEY4IQXGLDA3FUBE7EW2XDESAZ6JGI2TB3WPNQWSNJPGQVFAKHMNUMB2T5PIVMG3X3HZSZU6Z7ES7WMSHZDLVUCDBCYTDRCC4ZMMDMWXRXDHQ7WUHLISPYU7RSWJYVDGDHNBIGEPD7YSQU","b-sec":"BETZUC2ABPFJTVGLDWCC5GGZ37FEM33KF3EAOHUVAR3J3G32RQFHZ26B5F2EZYZ7"}

    patterns = (
        '<meta[\s]*http-equiv[\s]*=[\s]*[\'"]refresh[\'"][\s]*content[\s]*=[\s]*[\'"]\d+[\s]*;[\s]*url[\s]*=[\s]*(.*?)[\'"][\s]*/?>',
        'window.location[\s]*=[\s]*[\'"](.*?)[\'"][\s]*;',
        'window.location.href[\s]*=[\s]*[\'"](.*?)[\'"][\s]*;',
        'window.location.replace[\s]*\([\'"](.*?)[\'"]\)[\s]*;',
        'window.navigate[\s]*\([\'"](.*?)[\'"]\)',
        'location.href[\s]*=[\s]*[\'"](.*?)[\'"]',
    )

    urls = []
    results = []
    ips=[]
    flag = False
    parser = argparse.ArgumentParser(prog='owt.py', description="Obtain WebSite Title")
    parser.add_argument("-t", dest='target', default='urls.txt', help="target with [file-path] or [single-url]")
    parser.add_argument("-x", dest='threads', default=20, type=int, help="number of concurrent threads")
    parser.add_argument("-p", dest='ports', default="80,443,8080,8443", help="diy the scan's ports")
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    target = args.target
    threads = args.threads
    ports = args.ports.split(',')
    ##ports异常输入待实现
    if os.path.isfile(target):
        with open(target, 'r') as f:
            for line in f.readlines():
                for p in ips:
                    if ('.'.join(line.strip().split('.')[:3])) == p:
                        flag = True
                        break;
                if flag == True:
                    continue
                cip=line.strip()
                ips.append('.'.join(cip.split('.')[:3]))
                for ip in range(1,255):
                    cip='.'.join(cip.split('.')[:3])+"."+str(ip)
                    for port in ports:
                        urls.append(cip+":"+str(port))
    else:
        targets=target.split(',')
        ##targets待实现targets异常输入判断
        for t in targets:
            for ip in range(1,255):
                cip = '.'.join(t.split('.')[:3])+"."+str(ip)
                for port in ports:
                    urls.append(cip+":"+str(port))
    try:
        pool = ThreadPool(threads)
        pool.map(get_title, urls)
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        exit("[*] User abort")