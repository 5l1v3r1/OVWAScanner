from bs4 import BeautifulSoup
import urllib
import logging
import sys
import re
from http.cookiejar import CookieJar
from urllib.request import urlopen
from utils.spider import crawler


logging.basicConfig(format='[%(asctime)s - %(levelname)s]: %(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S %p')


class NoRedirection(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


def possibly_error(css_class):
    return css_class is not None and ('error' in css_class or 'message'
                                      in css_class or 'err' in css_class)


def usage():
    print('''Usage: ./crosser -t (or --target) <url>
Available options:
-h  --help            | show this page
-r  --reverse         | reverse scan (all found inputs \
on all urls)
                      | DO NOT RUN -r ON BIG DYNAMIC SITES \
OR YOU\'LL WAIT FOREVER!!!
-c  --cookie <cookie> | provide cookie in string format \
('COOKIE=VALUE;C2=V2')
-t  --target <url>    | target url, provide with protocol \
('http:// or https://')''')
    sys.exit()


# check if forms have tokens
def check_availability(url, results, **kwargs):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 \
        Safari/537.36'})
    if 'cookie' in kwargs:
        cookies = CookieJar()
        opener = urllib.request.build_opener(
                 urllib.request.HTTPCookieProcessor(cookies))
        request.add_header('Cookie', kwargs['cookie'])
        resp = opener.open(request).read()
    else:
        resp = urlopen(request).read()
    soup = BeautifulSoup(resp, 'html5lib')
    logging.info('Finding forms')
    forms = soup.find_all('form')
    for form in forms:
        tokenfield = form.find('input', {'type': 'hidden'})
        logging.info('Finding hidden inputs')
        if tokenfield is None:
            formname = form['action'] if form.has_attr('action') \
                       else 'Some'
            logging.critical('\'' + formname +
                             '\' form on \'' + url + '\' doesn\'t have a' +
                             ' CSRF token!')
            results += ('\n[+]\'' + formname +
                        '\' form on \'' + url + '\' doesn\'t have a' +
                        ' CSRF token!')
        elif tokenfield is not None:
            if len(tokenfield['value']) < 10 \
               or re.match(r'^[0-9a-f]+$', tokenfield['value']) is None:
                    formname = form['action'] if form.has_attr('action') \
                               else 'Some'
                    logging.critical('\'' + formname +
                                     '\' form on \'' + url + '\' doesn\'t' +
                                     ' have a CSRF token!')
                    results += ('\n[+]\'' + formname +
                                '\' form on \'' + url + '\' doesn\'t' +
                                ' have a CSRF token!')
    return results


# check if tokens are changing with new request
def check_changing(url, results, **kwargs):
    tokenbase = {}
    newtokenbase = {}
    if 'cookie' in kwargs:
        cookies = CookieJar()
        opener = urllib.request.build_opener(
                 urllib.request.HTTPCookieProcessor(cookies))
        request = urllib.request.Request(url)
        request.add_header('Cookie', kwargs['cookie'])
        resp = opener.open(request).read()
    else:
        resp = urlopen(url).read()
    soup = BeautifulSoup(resp, 'html5lib')
    forms = soup.find_all('form')
    for form in forms:
        tokenfield = form.find('input', {'type': 'hidden'})
        if tokenfield is not None and form.has_attr('action'):
            if len(tokenfield['value']) > 10 \
             and re.match(r'^[0-9a-f]+$', tokenfield['value']) is not None:
                tokenbase[form['action']] = tokenfield['value']
    if 'cookie' in kwargs:
        newresp = opener.open(request).read()
    else:
        newresp = urlopen(url).read()
    newsoup = BeautifulSoup(newresp, 'html5lib')
    newforms = newsoup.find_all('form')
    for form in newforms:
        tokenfield = form.find('input', {'type': 'hidden'})
        if tokenfield is not None and form.has_attr('action'):
            if len(tokenfield['value']) > 10 \
             and re.match(r'^[0-9a-f]+$', tokenfield['value']) is not None:
                newtokenbase[form['action']] = tokenfield['value']
    logging.info('Found tokens: ' + str(tokenbase))
    for key in tokenbase:
        if tokenbase[key] == newtokenbase[key]:
            formname = form['action'] if form.has_attr('action') \
                       else 'Some'
            logging.critical('\'' + formname +
                             '\' on \'' + url + '\' : form token' +
                             'does not change!')
            results += ('\n[+]\'' + formname +
                        '\' on \'' + url + '\' : form token' +
                        'does not change!')
    return results


# check reusable csrf vulnerability
def check_reusable(url, results, **kwargs):
    cookies = CookieJar()
    nonredirectopener = urllib.request.build_opener(
                            NoRedirection,
                            urllib.request.HTTPCookieProcessor(cookies))
    usualopener = urllib.request.build_opener(
                            urllib.request.HTTPCookieProcessor(cookies))
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 \
        Safari/537.36'})
    if 'cookies' in kwargs:
        request.add_header('Cookie', kwargs['cookie'])
    resp = nonredirectopener.open(request)
    content = resp.read()
    soup = BeautifulSoup(content, 'html5lib')
    forms = soup.find_all('form')
    for form in forms:
        try:
            tokenfields = form.find_all('input', {'type': 'hidden'})
            tokens = []
            for tokenfield in tokenfields:
                if len(tokenfield['value']) > 10 \
                 and re.match(r'^[0-9a-f]+$', tokenfield['value']) is not None:
                    tokens.append(tokenfield['value'])
            logging.info('Tokens found: ' + str(len(tokens)))
            if len(tokens) > 0:
                for token in tokens:
                    csrf = token
                    inputs = {inp['name']: inp['type'] for
                              inp in form.find_all('input')}
                    data = {}
                    for inp in inputs:
                        if inputs[inp] == 'hidden':
                            data[inp] = csrf
                        elif inputs[inp] == 'submit':
                            data[inp] = inp
                        else:
                            data[inp] = '123'
                    encrdata = urllib.parse.urlencode(data)
                    encrdata = encrdata.encode('ascii')
                    tempreq = urllib.request.Request(url, encrdata, headers={
                        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
                        AppleWebKit/537.36 (KHTML, like Gecko) \
                        Chrome/35.0.1916.47 Safari/537.36'})
                    if 'cookies' in kwargs:
                        tempreq.add_header('Cookie', kwargs['cookie'])
                    for i in range(3):
                        nonredirectopener.open(tempreq)
                    finalresp = usualopener.open(tempreq)
                    cont = finalresp.read()
                    soup = BeautifulSoup(cont, 'html5lib')
                    errors = soup.find_all(class_=possibly_error)
                    repeatederrors = []
                    for i in range(len(errors)):
                        for j in range(i+1, len(errors)):
                            if errors[i].string == errors[j].string and \
                               errors[i].parent == errors[j].parent:
                                if errors[i] not in repeatederrors:
                                    repeatederrors.append(errors[i])
                                if errors[j] not in repeatederrors:
                                    repeatederrors.append(errors[j])
                    if len(repeatederrors) > 0:
                        formname = form['action'] if form.has_attr('action') \
                                   else 'Some'
                        logging.critical('\'' + formname +
                                         '\' form on \'' + url + '\' token' +
                                         ' is reusable!')
                        results += ('\n[+]\'' + formname +
                                    '\' form on \'' + url + '\' token' +
                                    ' is reusable!')
        except Exception as e:
            print(e)
    return results


available_options = ['-r', '--reverse', '-h', '--help']
available_vars = ['-c', '--cookie', '-t', '--target']


def main(argv):
    print('''
=====================================

    ░█▀▀░█▀▄░█▀█░█▀▀░█▀▀░█▀▀░█▀▄
    ░█░░░█▀▄░█░█░▀▀█░▀▀█░█▀▀░█▀▄
    ░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀

       v.0.0.1 - by skvot3r
======================================''')
    kwargs = {}
    recursive = False
    if len(argv) == 0:
        logging.error("No target provided!")
        usage()
    results = 'Found possible CSRF vulnerabilities:'
    # print(argv)
    for argument in argv:
        if argument in ('-h', '--help'):
            usage()
        elif argument in ('-c', '--cookie'):
            cookie = argv[argv.index(argument)+1]
            kwargs['cookie'] = cookie
        elif argument in ('-t', '--target'):
            target = argv[argv.index(argument)+1]
        elif argument in ('-r', '--reverse'):
            recursive = True
        elif (argument not in (available_options, available_vars)
                and argv[argv.index(argument)-1] not in available_vars):
            logging.error("Unknown command " + str(argument))
            usage()
        elif argument in available_vars and argument not in available_options:
            if (argv.index(argument) == len(argv)-1
                or argv[argv.index(argument)+1] in available_options
                    or argv[argv.index(argument)+1] in available_vars):
                logging.error(str(argument) +
                              " doesn\'t have any arguments")
                usage()
    if 'target' not in locals():
        logging.error("No target provided!")
        usage()
    results = check_availability(target, results, **kwargs)
    results = check_changing(target, results, **kwargs)
    results = check_reusable(target, results, **kwargs)
    if recursive:
        urls = crawler(target, **kwargs)
        print(urls)
        for page in urls:
            logging.info('Request is processing')
            results = check_availability(page, results, **kwargs)
            results = check_changing(page, results, **kwargs)
            results = check_reusable(page, results, **kwargs)

    return results


if __name__ == '__main__':
    main(sys.argv[1:])
