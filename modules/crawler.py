from MRequest.request import *
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import os
from concurrent.futures import ThreadPoolExecutor
def GetHref(html):
    soup = BeautifulSoup(html, "lxml")
    hreflist = []
    for link in soup.findAll('a'):
        href = link.get('href')
        if href and "#" not in href and "mailto" not in href and "javascript:" not in href:
            hreflist.append(href)
    return set(hreflist)

def GetCurrentDir(url):
    urllen = len(url)
    for i in range(1, urllen):
        if "/" in url[-i:]:
            return url[:urllen - i + 1]
        elif "." in url[-i:]:
            while "/" not in url[-i:]:
                i += 1
            return url[:urllen - i + 1]
    return False

def CraftURL(url, href):
    href = href.replace("./", "")
    if url[-1:] != "/" and os.path.splitext(urlparse.urlparse(url).path)[0] == "":
        url = url + "/"
    urlsplited = urlparse.urlsplit(url)
    if href[:1] == "/":
        return urlsplited.scheme + "://" + urlsplited.netloc + href
    else:
        return GetCurrentDir(urlsplited.scheme + "://" + urlsplited.netloc + urlsplited.path) + href

def GetLinks(url, html):
    hrefset = GetHref(html)
    links = []
    urlsplited = urlparse.urlsplit(url)
    baseurl = urlsplited.scheme + "://" + urlsplited.netloc
    for href in hrefset:
        if href[:7] != "http://" and href[:8] != "https://":
            links.append(CraftURL(url, href))
        elif href[:len(baseurl)] == baseurl:
            links.append(href)
    return links
def crawler_links(url,total):
    listcrawler=[]
    a=NRequests()
    a.sendGet(url)
    b=ThreadPoolExecutor().submit(GetLinks,url,a.source()).result()
    dem=0
    for i in b:
        if total==0:
            break
        d=NRequests()
        d.sendGet(i)
        c=ThreadPoolExecutor(max_workers=len(b)).submit(GetLinks,i,d.source()).result()
        total-=1
        for j in c:
            if j not in b:
                b.append(j)
        dem+=1
        listcrawler.append(i)
    return listcrawler
    #return b