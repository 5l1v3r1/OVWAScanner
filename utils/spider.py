from bs4 import BeautifulSoup
from urllib import request, parse
from http.cookiejar import CookieJar
import re

urls = []
checked_adresses = []


regex = re.compile(
        r'^[a-z0-9\.\/\\\:_]+$', re.IGNORECASE)


def samedomain(netloc1, netloc2):
    """Determine whether two netloc values are the same domain.
    This function does a "subdomain-insensitive" comparison. In other words ...
    samedomain('www.microsoft.com', 'microsoft.com') == True
    samedomain('google.com', 'www.google.com') == True
    samedomain('api.github.com', 'www.github.com') == True
    """
    domain1 = netloc1.lower()
    if '.' in domain1:
        domain1 = domain1.split('.')[-2] + '.' + domain1.split('.')[-1]

    domain2 = netloc2.lower()
    if '.' in domain2:
        domain2 = domain2.split('.')[-2] + '.' + domain2.split('.')[-1]

    return domain1 == domain2


def getlinks(pageurl, domain, soup):
    """Returns a list of links from from this page to be crawled.
    pageurl = URL of this page
    domain = domain being crawled (None to return links to *any* domain)
    soup = BeautifulSoup object for this page
    """

    # get target URLs for all links on the page
    links = [a.attrs.get('href') for a in soup.select('a[href]') if
             'logout' not in a['href']]
    # print(links)
    # remove fragment identifiers
    links = [parse.urldefrag(link)[0] for link in links]
    # print(links)
    # remove any empty strings
    links = [link for link in links if link]
    # print(links)
    # if it's a relative link, change to absolute
    links = [link if bool(parse.urlparse(link).netloc) else
             parse.urljoin(pageurl, link)
             for link in links if regex.match(link)]
    # print(links)
    # if only crawing a single domain, remove links to other domains
    if domain:
        links = [link for link in links
                 if samedomain(parse.urlparse(link).netloc, domain) and
                 regex.match(link)]
        # print(links)
    return links


def url_in_list(url, listobj):
    """Determine whether a URL is in a list of URLs.
    This function checks whether the URL is contained in the list with either
    an http:// or https:// prefix. It is used to avoid crawling the same
    page separately as http and https.
    """
    http_version = url.replace('https://', 'http://')
    https_version = url.replace('http://', 'https://')
    return (http_version in listobj) or (https_version in listobj)


def crawler(startpage, **kwargs):
    pagequeue = []  # queue of pages to be crawled
    pagequeue.append(startpage)
    crawled = []  # list of pages already crawled
    domain = parse.urlparse(startpage).netloc

    while pagequeue:
        url = pagequeue.pop(0)  # get next page to crawl (FIFO queue)
        # print(url)
        # read the page
        req = request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
            AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 \
            Safari/537.36'})
        if 'cookie' in kwargs:
            cookies = CookieJar()
            opener = request.build_opener(
                     request.HTTPCookieProcessor(cookies))
            req.add_header('Cookie', kwargs['cookie'])
            resp = opener.open(req)
            resp.text = resp.read()
        else:
            resp = request.urlopen(req)
            resp.text = resp.read()
        if not resp.headers['content-type'].startswith('text/html'):
            continue  # don't crawl non-HTML content

        # Note that we create the Beautiful Soup object here (once) and pass it
        # to the other functions that need to use it
        soup = BeautifulSoup(resp.text, "html.parser")
        # process the page
        crawled.append(url)
        links = getlinks(url, domain, soup)
        # print(links)
        for link in links:
            if not url_in_list(link, crawled) \
               and not url_in_list(link, pagequeue):
                pagequeue.append(link)

    return crawled
