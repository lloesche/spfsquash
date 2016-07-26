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
    p = argparse.ArgumentParser(description='Optimize SPF Record')
    p.add_argument('--domain',  help='Domain name', required=True, dest='domain')
    p.add_argument('--realspf', help='Real TXT SPF record to optimize', required=True, dest='spf')
    p.add_argument('--qualifier', help='ALL Qualifier [+?~-],', default='~', dest='qualifier',
                   choices=['+', '?', '~', '-'])
    args = p.parse_args(argv)

    d = SPF(qualifier=args.qualifier)
    pprint(d.spf_record(d.squash(args.spf)))


class SPF:
    def __init__(self, qualifier='~'):
        self.log = logging.getLogger(self.__class__.__name__)
        self.lookups = 0
        self.qualifier = qualifier
        self.TXT_MAX_LEN = 255

    def spf_record(self, txt):
        records = []
        record = txt[0]
        e = 1
        while e <= len(txt):
            record += ' '+txt[e]
            e += 1

        return records

    def squash(self, record):
        self.lookups = 0
        squashed_spf = ['v=spf1']
        squashed_spf.extend(sorted(list(set(self.spf(record)))))
        squashed_spf.append(self.qualifier+'all')
        self.log.info('Total lookups: {}'.format(self.lookups))
        pprint(squashed_spf)
        return squashed_spf

    def spf(self, domain):
        self.log.info('Looking up SPF records in {}'.format(domain))
        elements = []
        for txt in self.txt(domain):
            txt = self.rfc4408_313_parser(txt)
            if self.isspf(txt):
                self.log.debug('TXT: {}'.format(txt))
                for element in txt.split(' ')[1:]:
                    element = element.lower()
                    if element.startswith('include:'):
                        elements.extend(self.spf(element[8:]))
                    elif element.endswith('all'):
                        self.log.info('Ignoring {}'.format(element))
                    else:
                        if element.startswith('ptr'):
                            self.log.warn('Found deprecated PTR entry {}'.format(element))
                            self.lookups += 1
                        elif element == 'a' or element == 'mx':
                            self.lookups += 1
                        elements.append(element)
        return elements

    def txt(self, domain):
        try:
            self.lookups += 1
            return dns.resolver.query(domain, 'TXT')
        except dns.exception.DNSException:
            self.log.error('No TXT record present for {}'.format(domain))
            return []

    def rfc4408_313_parser(self, txt):
        """https://tools.ietf.org/html/rfc4408#section-3.1.3
        """
        return ' '.join(str(txt)[1:-1].split()).replace('" "', '')

    def isspf(self, txt):
        return str(txt).lower().startswith('v=spf1')


if __name__ == "__main__":
    main(sys.argv[1:])