#!/usr/bin/env python
# Copyright (C) 2007-2016 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
#         Jamie Strandboge <jamie@canonical.com>
#         Steve Beattie <steve.beattie@canonical.com>
# License: GPLv3

from __future__ import print_function

import os, sys, tempfile, time, shutil, launchpadlib
from launchpadlib.launchpad import Launchpad
from launchpadlib.credentials import Credentials
import launchpadlib.errors
import io
import webbrowser

try:
    import progressbar
except ImportError:
    pass

# as of 16.04, launchpadlib supports python3
# so make code support both python2 and python3
if sys.version_info > (3, 0):
    string_types = (str,)
    from http.cookiejar import LoadError, MozillaCookieJar
    from urllib.request import HTTPCookieProcessor, HTTPError, build_opener
    from urllib.parse import unquote
else:
    string_types = (basestring,)
    from cookielib import LoadError, MozillaCookieJar
    from urllib2 import HTTPCookieProcessor, HTTPError, build_opener
    from urllib import unquote

version_min = [1,5,7]
lp_version = launchpadlib.__version__
if not isinstance(lp_version, string_types):
    lp_version = lp_version.decode()

if version_min > list(map(int, lp_version.split('.'))):
    raise ValueError("Requires launchpadlib version %s or later (%s in use)" \
        % (".".join(map(str, version_min)), lp_version))

def connect(use_edge=False, beta=False, version=None, uri=None, bot=None):

    # Use of edge is obsoleted
    # See: http://blog.launchpad.net/general/edge-is-deprecated
    if use_edge == True:
        raise ValueError("Use of use_edge=True with connect() is obsoleted, see comments in lpl_common.py.")

    cachedir = os.path.expanduser('~/.launchpadlib/cache')
    if not os.path.exists(cachedir):
        os.makedirs(cachedir, 0o700)

    if beta:
        version="beta"
    elif not version:
        version="1.0"
    elif version:
        version=version

    root = 'production'
    credfile = os.path.expanduser('~/.launchpadlib/credentials-lpnet')
    if uri:
        root = uri
        credfile = os.path.expanduser('~/.launchpadlib/credentials-%s' % (uri.replace('/','_')))
    if bot:
        credfile = credfile.replace('credentials', 'bot-credentials')
    launchpad = Launchpad.login_with(sys.argv[0], service_root=root, launchpadlib_dir=cachedir, credentials_file=credfile, version=version)
    return launchpad

def save(item):
    # attempt to deal with intermittent failures
    count = 0
    max_tries = 10
    result = False
    err_str = ""
    while not result and count < max_tries:
        try:
            item.lp_save()
            result = True
        except launchpadlib.errors.HTTPError as error:
            err_str = "save() failed: %s" % (error.content)
            count += 1
            time.sleep(5)

    if not result:
        print("%s (tried %d times)" % (err_str, max_tries), file=sys.stderr)
    return result

def extract_task(task):
    name = task.bug_target_name.lower()
    package = None
    distribution = None
    series = None
    if ' (' in name:
        package, distribution = name.split(' (',1)
        distribution = distribution.split(')')[0]
    else:
        package = name
    if distribution and ' ' in distribution:
        distribution, series = distribution.split(' ',1)

    return package, distribution, series

def split_ppa(group):
    if '/' in group:
        group, ppa = group.split('/',1)
    else:
        ppa = 'ppa'
    return group, ppa

def get_archive(name, lp, verbose=False, distribution=None):
    if name == 'ubuntu':
        if verbose:
            print("Loading Ubuntu Archive ...")
        if distribution == None:
            distribution = lp.distributions[name]
        archive, partner = distribution.archives
        group = 'ubuntu'
        ppa = None
    else:
        group, ppa = split_ppa(name)
        if verbose:
            print("Loading %s '%s' PPA ..." % (group, ppa))
        if distribution is None:
            archive = lp.people[group].getPPAByName(name=ppa)
        else:
            archive = lp.people[group].getPPAByName(name=ppa,
                                                    distribution=distribution)
    return archive, group, ppa


def opener_with_cookie(cookie_file):
    import sqlite3 as sqlite

    old_umask = os.umask(0o077)
    if cookie_file.endswith('.sqlite'):
        try:
            src = sqlite.connect(cookie_file)
            db_dump = io.StringIO()
            for line in src.iterdump():
                db_dump.write('%s\n' % line)
            src.close()
            con = sqlite.connect(':memory:')
            con.cursor().executescript(db_dump.getvalue())
            db_dump.close()
        except sqlite.OperationalError:
            # Work around Firefox 3.5's dumb sqlite locking problems by copying cookies out
            # We cannot make this an in-memory file as sqlite3 has no capabilities to load them.
            with tempfile.NamedTemporaryFile(prefix='cookies-XXXXXX', suffix='.sqlite') as sql_handle:
                sql = sql_handle.name
            shutil.copyfile(cookie_file, sql)
            con = sqlite.connect(sql)

        match = '%launchpad.net'
        cur = con.cursor()
        cur.execute("select host, path, isSecure, expiry, name, value from moz_cookies where host like ?", [match])
        ftstr = ["FALSE","TRUE"]
        cookie_file_dump = io.StringIO()

        cookie_file_dump.write("# HTTP Cookie File\n")
        for item in cur.fetchall():
            str = "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ( item[0], \
                   ftstr[item[0].startswith('.')], item[1], \
                   ftstr[item[2]], item[3], item[4], item[5])
            cookie_file_dump.write(str)
        sql = None
        cookie_file_dump.flush()
        cookie_file_dump.seek(0)
        con.close()

    cj = MozillaCookieJar()
    try:
        cj._really_load(cookie_file_dump, '', False, False)
    except LoadError as e:
        print("Failed to load cookie from file (%s): %s - continuing anyway..." % (cookie_file, e.strerror))
    opener = build_opener(HTTPCookieProcessor(cj))

    os.umask(old_umask)
    cookie_file_dump.close()
    # Ensure that the lp token (if any) is a valid token 
    response = open_url(opener, 'https://launchpad.net')
    if 'Log in' in response.read().decode():
        print('User is not logged in. Please log in...')
        webbrowser.get('firefox').open('https://launchpad.net/ubuntu/+login')
        input('Press any key after logging in. (Firefox must be closed in order to grab the updated cookies)')
        return opener_with_cookie(cookie_file)

    return opener

def open_url(opener, url):
    tries = 0
    max_tries = 10
    while True:
        try:
            page = opener.open(url)
            break
        except HTTPError as e:
            tries += 1
            if tries >= max_tries or (e.code not in (500, 502, 503, 504)):
                print("Failed (%s): %d %s" % (url, e.code, e.msg), file=sys.stderr)
                raise
            time.sleep(3)

    return page

def chunked_read(response, chunk_size=8192, outfile=None, verbose=True):
    info = response.info()
    if hasattr(info, 'getheader'):
        header = info.getheader('Content-Length')
    else:
        header = response.headers.get('Content-Length')
    total_size = int(header.strip())
    bytes_so_far = 0

    try:
        widgets = [progressbar.Percentage(), ' ',
                   progressbar.Bar(marker='=', left='[', right=']'),
                   ' ', str(total_size), ' ', progressbar.ETA()]
    except:
        raise ValueError("Please install python-progressbar to use 'download'")

    bar = None
    if verbose and sys.stdout.isatty():
        bar = progressbar.ProgressBar(widgets=widgets, maxval=total_size).start()

    while 1:
        chunk = response.read(chunk_size)
        if not chunk:
            break
        bytes_so_far += len(chunk)
        if bar:
            bar.update(bytes_so_far)
        if outfile:
            outfile.write(chunk)

    if bar:
        bar.finish()
    return bytes_so_far

def download(opener_or_lp, url, filename=None, verbose=True, dryrun=False, rewrite_uri=False):
    if verbose:
        print("  %s ..." % (url))
        if dryrun:
            print("(dry run, skipping)")
    if dryrun:
        return

    if not filename:
        filename = os.path.basename(unquote(url))

    if os.path.exists(filename):
        print("(already exists, skipping)")
        return

    tmp = tempfile.NamedTemporaryFile(delete=False)

    if type(opener_or_lp) == Launchpad:
        lp = opener_or_lp
        lp_api_root_uri = str(lp._root_uri)
        lp_root_uri = 'https://launchpad.net/'
        if rewrite_uri and url.startswith(lp_root_uri):
            url = url.replace(lp_root_uri, lp_api_root_uri)
        contents = lp._browser.get(url)
        tmp.write(contents)
    else:
        opener = opener_or_lp
        response = open_url(opener, url)
        chunked_read(response, outfile=tmp, verbose=verbose)
    tmp.close()
    shutil.move(tmp.name,filename)

    return filename
