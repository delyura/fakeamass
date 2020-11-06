import aiohttp
import asyncio
import requests
import re
import sys

argc = len(sys.argv)
if argc == 1:
    print("Usage: \n\tpython3 fakeamass.py foo.com")
    sys.exit()
else:
    domain = sys.argv[1]
	
# API key http://securitytrails.com/ 
api_tr = ''
#API key https://virustotal.com
api_vt = ''

if len(api_tr) == 0 or len(api_vt) == 0:
    print("Missing APIkeys")
    sys.exit()

    
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

	
print(f"""{bcolors.FAIL}
  █████▒▄▄▄       ██ ▄█▀▓█████     ▄▄▄       ███▄ ▄███▓ ▄▄▄        ██████   ██████ 
▓██   ▒▒████▄     ██▄█▒ ▓█   ▀    ▒████▄    ▓██▒▀█▀ ██▒▒████▄    ▒██    ▒ ▒██    ▒ 
▒████ ░▒██  ▀█▄  ▓███▄░ ▒███      ▒██  ▀█▄  ▓██    ▓██░▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   
░▓█▒  ░░██▄▄▄▄██ ▓██ █▄ ▒▓█  ▄    ░██▄▄▄▄██ ▒██    ▒██ ░██▄▄▄▄██   ▒   ██▒  ▒   ██▒
░▒█░    ▓█   ▓██▒▒██▒ █▄░▒████▒    ▓█   ▓██▒▒██▒   ░██▒ ▓█   ▓██▒▒██████▒▒▒██████▒▒
 ▒ ░    ▒▒   ▓▒█░▒ ▒▒ ▓▒░░ ▒░ ░    ▒▒   ▓▒█░░ ▒░   ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
 ░       ▒   ▒▒ ░░ ░▒ ▒░ ░ ░  ░     ▒   ▒▒ ░░  ░      ░  ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░
 ░ ░     ░   ▒   ░ ░░ ░    ░        ░   ▒   ░      ░     ░   ▒   ░  ░  ░  ░  ░  ░  
             ░  ░░  ░      ░  ░         ░  ░       ░         ░  ░      ░        ░ 
{bcolors.ENDC}"""
)
print()
print(f"""{bcolors.WARNING}Search...{bcolors.ENDC}""")


async def trails(domain, apikey):
    try:
        async with aiohttp.ClientSession() as session:
            url = 'https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false' % domain
            headers = {'Content-Type':'application/json', 'APIKEY':'%s' % apikey}
            res_tr = []
            async with session.get(url, headers=headers) as response:
                r = await response.json()
                l = len(r['subdomains'])
                for i in range(0,l,1):
                    a = r['subdomains'][i]
                    res_tr.append(a+'.%s' % domain)

                return res_tr
    except:
        pass
			

loop = asyncio.get_event_loop()
a=loop.run_until_complete(trails(domain, api_tr))


async def vt(domain, apikey):
    try:
        async with aiohttp.ClientSession() as session:
            url = 'https://www.virustotal.com/api/v3/domains/%s/subdomains' % domain
            headers = {'x-apikey':'%s' % (apikey)}
            res_vt = []
            async with session.get(url, headers=headers) as response:
                r = await response.json()
                l = len(r['data'])
                for i in range(0,l,1):
                    a = r['data'][i]['id']
                    res_vt.append(a)
        return res_vt
    except:
        pass


loop = asyncio.get_event_loop()
b = loop.run_until_complete(vt(domain,api_vt))


async def crt(domain):
    try:
        async with aiohttp.ClientSession() as session:
            url = 'https://crt.sh/?q=%s' % domain
            async with session.get(url) as response:
                r = await response.text()
                pattern = r'[.a-zA-Z0-9-_]+\.%s' % domain
                res_crt = re.findall(pattern, r)
                res=set(res_crt)
                return res
    except:
        pass


loop = asyncio.get_event_loop()
c=loop.run_until_complete(crt(domain))


result= list(set(a+b+list(c)))


for i in range(0,len(result),1):
    print(f"""{bcolors.OKGREEN}%s{bcolors.ENDC}""" % (result[i]))


print(f"""{bcolors.WARNING}Total number of subdomains :%s{bcolors.ENDC}""" % (len(result)))
