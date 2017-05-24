# from blindelephant.Fingerprinters import WebAppFingerprinter
import subprocess
from urllib.request import urlparse
import socket
from utils.crosser import main
from utils.sqlmapper import sqlmapper
from utils.xss import xsser
import json

# results = ''


def performscan(task):
    results = {}
    results['host'] = {}
    print(results)
    if task.portscan:
        print('Scanning ports...')
        ip = socket.gethostbyname(urlparse(task.url).netloc)
        command = subprocess.run(["nmap", "-sV", ip], stdout=subprocess.PIPE)
        results['host']['nmap'] = command.stdout.decode("utf-8")
        task.save()
        print('Scanned ports.')
        task.progress += 10
        task.save()
    if task.cms:
        print('Scanning cms...')
        command = subprocess.run(["/opt/cmsmap/cmsmap.py", "-t",
                                  urlparse(task.url).netloc],
                                 stdout=subprocess.PIPE)
        results['host']['cmsmap'] = 'cmsmap:'
        temp = command.stdout.decode("utf-8")
        for line in temp.split('\n'):
            if line.startswith('[M]'):
                results['host']['cmsmap'] += '\n' + line
        if len(results['host']['cmsmap'].split('\n')) == 1:
            results['host'].pop('cmsmap')
        task.progress += 10
        task.save()
    if task.nikto:
        for subtask in task.subtask_set.all():
            if subtask.url not in results:
                results[subtask.url] = {}
            print('Scanning nikto...')
            command = subprocess.run(["nikto", "-h", task.url],
                                     stdout=subprocess.PIPE)
            results[subtask.url]['nikto'] = command.stdout.decode("utf-8")
            print('Scanned nikto.')
            subtask.progress += 25
            subtask.save()
        task.progress += 20
        task.save()
    if task.sql:
        for subtask in task.subtask_set.all():
            if subtask.url not in results:
                results[subtask.url] = {}
            print('Scanning sql...')
            if not task.cookie:
                results[subtask.url]['sql'] = sqlmapper(subtask.url)
            else:
                results[subtask.url]['sql'] = sqlmapper(subtask.url,
                                                        cookie=task.cookie)
            if len(results[subtask.url]['sql'].split('\n')) == 1:
                results[subtask.url].pop('sql')
            print('Scanned sql.')
            subtask.progress += 25
            subtask.save()
        task.progress += 20
        task.save()
    if task.xss:
        for subtask in task.subtask_set.all():
            if subtask.url not in results:
                results[subtask.url] = {}
            print('Scanning xss...')
            if not task.cookie:
                results[subtask.url]['xss'] = xsser(subtask.url)
            else:
                results[subtask.url]['xss'] = xsser(subtask.url,
                                                    cookie=task.cookie)
            if len(results[subtask.url]['xss'].split('\n')) == 1:
                results[subtask.url].pop('xss')
            print('Scanned xss.')
            subtask.progress += 25
            subtask.save()
        task.progress += 20
        task.save()
    if task.csrf:
        for subtask in task.subtask_set.all():
            if subtask.url not in results:
                results[subtask.url] = {}
            print('Scanning csrf...')
            if not task.cookie:
                results[subtask.url]['csrf'] = main(['-t', subtask.url])
            else:
                results[subtask.url]['csrf'] = main(['-t', subtask.url,
                                                     '-c', task.cookie])
            if len(results[subtask.url]['csrf'].split('\n')) == 1:
                results[subtask.url].pop('csrf')
            print('Scanned csrf.')
            subtask.progress += 25
            subtask.save()
    task.results = results['host']
    task.save()
    for subtask in task.subtask_set.all():
        if subtask.url not in results:
            results[subtask.url] = {}
        subtask.results = results[subtask.url]
        subtask.progress = 100
        subtask.save()
    task.progress = 100
    task.save()
