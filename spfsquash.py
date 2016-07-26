#!/usr/bin/env python3
import sys
import logging
import argparse
import dns.resolver
from pprint import pprint

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('SPF').setLevel(log_level)
log = logging.getLogger(__name__)


def main(argv):
    """Entry point

    """
    p = argparse.ArgumentParser(description='Squash SPF Record')
    p.add_argument('--domain',  help='Domain name', required=True, dest='domain')
    p.add_argument('--realspf', help='Real TXT SPF record to optimize', required=True, dest='spf')
    p.add_argument('--qualifier', help='ALL Qualifier [+?~-],', default='~', dest='qualifier',
                   choices=['+', '?', '~', '-'])
    args = p.parse_args(argv)

    d = SPF(domain=args.domain, qualifier=args.qualifier)
    new_spf = d.spf_record(d.squash(args.spf))
    for txt in new_spf:
        print(txt)


class SPF:
    def __init__(self, domain, qualifier='~'):
        self.log = logging.getLogger(self.__class__.__name__)
        self.lookups = 0
        self.domain = domain
        self.qualifier = qualifier
        self.TXT_MAX_LEN = 255

    def spf_record(self, txt):
        self.log.info('Assembling final TXT record')
        records = []
        record = 'v=spf1'
        for e in txt:
            if len(record + ' ' + e) <= self.TXT_MAX_LEN:
                record += ' ' + e
            else:
                self.log.debug('Creating record with len {}: "{}"'.format(len(record), record))
                records.append(record)
                record = ' ' + e

        self.log.debug('Creating record with len {}: "{}"'.format(len(record), record))
        records.append(record)
        return records

    def squash(self, record):
        self.lookups = 0
        squashed_spf = []
        squashed_spf.extend(sorted(list(set(self.spf(record)))))
        squashed_spf.append(self.qualifier+'all')
        self.log.info('Total lookups: {}'.format(self.lookups))
        return squashed_spf

    def spf(self, domain, recurse=True):
        self.log.info('Looking up SPF records in {}'.format(domain))
        elements = []
        for txt in self.txt(domain):
            txt = self.rfc4408_313_parser(txt)
            if self.isspf(txt):
                self.log.debug('Processing SPF: {}'.format(txt))
                for element in txt.split(' ')[1:]:
                    element = element.lower()
                    if element.startswith('include:') and recurse:
                        elements.extend(self.spf(element[8:], recurse))
                    elif element.endswith('all'):
                        self.log.debug('Ignoring {}'.format(element))
                    elif element == 'a':
                        self.log.info('Found "a" in SPF record')
                        elements.extend(self.a(self.domain))
                        elements.extend(self.aaaa(self.domain))
                    elif element == 'mx':
                        self.log.info('Found "mx" in SPF record')
                        elements.extend(self.mx(self.domain, resolve=True))
                    else:
                        if element.startswith('ptr'):
                            self.log.warn('Found deprecated PTR entry {}'.format(element))
                            self.lookups += 1
                        elements.append(element)
        return elements

    def txt(self, domain):
        return [str(a) for a in self.query(domain, 'TXT')]

    def a(self, domain):
        return ['ip4:'+str(a) for a in self.query(domain, 'A')]

    def aaaa(self, domain):
        return ['ip6:'+str(a) for a in self.query(domain, 'AAAA')]

    def mx(self, domain, resolve=False):
        records = []
        results = self.query(domain, 'MX')
        if resolve:
            for result in results:
                records.extend(self.a(str(result.exchange)))
                records.extend(self.aaaa(str(result.exchange)))
        else:
            records.extend(['mx:'+str(a.exchange) for a in results])
        return records

    def query(self, domain, type):
        self.log.debug('Performing {} record lookup for {}'.format(type, domain))
        try:
            self.lookups += 1
            records = dns.resolver.query(domain, type)
            self.log.debug('Found: ' + ', '.join([str(a) for a in records]))
            return records
        except dns.exception.DNSException:
            self.log.warn('No {} record present for {}'.format(type, domain))
            return []

    def rfc4408_313_parser(self, txt):
        """https://tools.ietf.org/html/rfc4408#section-3.1.3
        """
        return ' '.join(txt[1:-1].split()).replace('" "', '')

    def isspf(self, txt):
        return txt.lower().startswith('v=spf1')


if __name__ == "__main__":
    main(sys.argv[1:])