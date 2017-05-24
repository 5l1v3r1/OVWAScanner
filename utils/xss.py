from bs4 import BeautifulSoup
from urllib import request
from http.cookiejar import CookieJar
import subprocess


def xsser(url, **kwargs):
    results = 'XSS in ' + url + ':'
    req = request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 \
        Safari/537.36'})
    if 'cookie' in kwargs:
        cookies = CookieJar()
        opener = request.build_opener(
                 request.HTTPCookieProcessor(cookies))
        req.add_header('Cookie', kwargs['cookie'])
        resp = opener.open(req).read()
    else:
        resp = request.urlopen(req).read()
    soup = BeautifulSoup(resp, 'html5lib')
    forms = soup.find_all('form')
    for form in forms:
        method = form['method']
        inps = form.find_all('input')
        if method.upper() == 'GET':
            params = [str(param['name']+'=1') for param in inps
                      if param.has_attr('name')]
            params2 = params[:]
            strings = []
            for par in params:
                params2.append(params2.pop(params2.index(par)))
                string = '?' + '&'.join(params2)
                strings.append(string[:-1])
            for string in strings:
                comparams = ["xsser", "-u", str(url), "-g", string]
                if 'cookie' in kwargs:
                    comparams.append("--cookie="+kwargs['cookie'])
                # print(comparams)
                command = subprocess.run(comparams,
                                         stdout=subprocess.PIPE)
                temp = command.stdout.decode("utf-8")
                for line in temp.split('\n'):
                    if 'List of possible XSS injections:' in line:
                        parameter = string.split('?')[1].split('&')[-1].split(
                                    '=')[0]
                        results += '\n[+] Parameter \'' + parameter + \
                                   '\' in the \'' + form['action'] + \
                                   '\' form is injectible'
    return results
