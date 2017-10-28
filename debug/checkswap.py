# scan checkswap file for interesting statistics
#
# Copyright 2017 Lou King
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from argparse import ArgumentParser
from csv import reader
from datetime import timedelta
from urllib2 import urlopen
from json import loads

from loutilities.textreader import TextDictReader
from loutilities.xmldict import XmlDictObject as DictObject

from loutilities.timeu import asctime
dtf = asctime('%Y-%m-%d %H:%M:%S')

NSFILTER = timedelta(minutes=15)

# checkswap records are datetime, recordtype, value
class CheckSwapRec (object):
    def __init__(self, row):
        for field in ['datetime', 'recordtype', 'value']:
            try:
                setattr(self, field, row.pop(0))
                if field == 'value':
                    self.value = int(self.value)
            except IndexError:
                setattr(self, field, None)

# check if row is start of netstat
# if it is, save datetime
def chknetstat(row):
    try:
        thisdt = dtf.asc2dt(row[0:19])
        rowsplit = row.split(' ')
        if rowsplit[2] == 'netstat':
            return thisdt
        else:
            return None

    # any exceptions mean some formatting error, didn't find the netstat
    except:
        return None

# check if row is start of new event
def chkevent(row):
    try:
        thisdt = dtf.asc2dt(row[0:19])
        return True
    except:
        return False

# generate output for netstat
def printnetstat(dt, netstat):
    iplist = {}
    try:
        while True:
            process = DictObject(netstat.next())
            if process.state in ['CLOSE_WAIT', 'TIME_WAIT']:
                thisip = process.foreignaddr.split(':')[0]
                try:
                    # filter out incomplete ip address, if ValueError then skip
                    test = tuple(int(p) for p in thisip.split('.'))
                    iplist[thisip] = iplist.get(thisip,0) + 1
                except ValueError:
                    pass
    except StopIteration:
        pass

    ipkeys = iplist.keys()
    ipkeys.sort(cmp=lambda x,y: cmp(tuple(int(p) for p in x.split('.')), tuple(int(p) for p in y.split('.'))))
    for ip in ipkeys:
        # http://ip-api.com/json/128.220.160.1
        # https://extreme-ip-lookup.com/json/128.220.160.1
        ipinfoobj = urlopen('https://extreme-ip-lookup.com/json/{}'.format(ip))
        ipinfo = DictObject(loads(ipinfoobj.read()))
        thisip = ip.split('.')
        thisip.reverse()
        revdns = urlopen('https://dns.google.com/resolve?name={}.in-addr.arpa&type=PTR'.format('.'.join(thisip)))
        revdnsdict = loads(revdns.read())
        if revdnsdict['Status'] == 0:
            host = revdnsdict['Answer'][0]['data']
        else:
            host = ''
        if ipinfo.status == 'success':
            print '"{}","{}","{}","{}","{}","{}","{}","{}","{}"'.format(dtf.dt2asc(dt), 
                                                   ip, 
                                                   iplist[ip], 
                                                   ipinfo.country,
                                                   ipinfo.region,
                                                   ipinfo.city,
                                                   ipinfo.isp,
                                                   ipinfo.org,
                                                   host)
        else:
            print '{},{},{}'.format(dtf.dt2asc(dt), ip, iplist[ip])

# do it
def main():
    parser = ArgumentParser()

    parser.add_argument('filename', help='name of file to filter')
    parser.add_argument('-m', '--mintrigger', help='find first instance below value, scan until above value', type=int)
    parser.add_argument('-b', '--debounce', help='hysteresis to avoid bouncing', type=int, default=0)
    parser.add_argument('-r', '--recovery', help='must recover by at least this much', type=int, default=50000)
    parser.add_argument('--netstat', action='store_true')

    args = parser.parse_args()

    ### parsing checkswap file
    # if mintrigger specified, flag first occurrence of free swap value <= mintrigger
    # start looking for trigger again when freeswap recovered at least recovery value and freeswap higher than mintrigger + debounce
    if args.mintrigger:
        state = 'search'
        lastvalue = 0
        laston = None
        lastondelta = None
        print 'timestamp,event,free swap,since last,low value'
        with open(args.filename, 'rb') as ckswapfile:
            ckswap = reader(ckswapfile)

            for row in ckswap:
                rec = CheckSwapRec(row)

                # show restarts, remembering last value seen
                if rec.recordtype == 'apache restart initiated':
                    print '{},restart,{}'.format(rec.datetime, lastvalue)
                if rec.value:
                    lastvalue = rec.value

                # only process free swap records now
                if rec.recordtype != 'free swap': continue

                # find value <= periodmin
                if state == 'search':
                    if rec.value <= args.mintrigger:
                        thistime = dtf.asc2dt(rec.datetime)
                        if laston:
                            lastondelta = thistime - laston
                            # see https://stackoverflow.com/questions/538666/python-format-timedelta-to-string
                            hrs, rem = divmod(lastondelta.total_seconds(), 3600)
                            mins, secs = divmod(rem, 60)
                            print '{},TRIGGERED,{},{:02d}:{:02d}:{:02d}'.format(rec.datetime, rec.value, int(hrs), int(mins), int(secs))
                        else:
                            print '{},TRIGGERED,{}'.format(rec.datetime, rec.value)
                        laston = thistime
                        state = 'found'
                        lowvalue = rec.value

                # find value > lowest value found + recovery, return to search state
                elif state == 'found':
                    lowvalue = min([lowvalue, rec.value])
                    if (rec.value > lowvalue + args.recovery) and (rec.value > args.mintrigger + args.debounce):
                        print '{},recovered,{},,{}'.format(rec.datetime, rec.value, lowvalue)
                        state = 'search'

    ### parsing checkswap-details file
    # display details on netstat command
    if args.netstat:
        state = 'search'    # search for netstat
        nsdt = dtf.asc2dt('1970-01-01 00:00:00')
        netstat = None
        nshdrs = {'foreignaddr':[['foreign', 'address']], 'state':['state'], 'pidprogram':[['pid/program', 'name']], 'timer':['timer']}
        nsreqdfields = ['foreignaddr']
        print 'timestamp,ip,count,country,region,city,isp,org,host'
        with open(args.filename) as details:
            for row in details:

                # looking for <date> <time> netstat
                if state == 'search':
                    thisdt = chknetstat(row)
                    # we only care about new netstats, not secondary ones
                    if thisdt and thisdt-nsdt > NSFILTER:
                        nsdt = thisdt
                        state = 'found'
                        ns = []

                # found netstat command
                elif state == 'found':
                    # if not at the end of the netstat command
                    if not chkevent(row):
                        ns.append(row)

                    # at the end, retrieve the data
                    else:
                        netstat = TextDictReader(list(ns), nshdrs, nsreqdfields, filetype='txt')
                        printnetstat(nsdt, netstat)
                        state = 'search'


###########################################################################################
#   __main__
###########################################################################################
if __name__ == "__main__":
    main()

