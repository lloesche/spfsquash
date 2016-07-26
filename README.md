# SPF Squash
SPF record squasher

## Intro
I ran into the problem that our company is including too many external services in our SPF record thereby exceeding the 10 lookup limit defined in RFC4408.

To work around the problem I hacked up this script which takes an invalid/too long SPF record ans squashes it into a shorter - hopefully valid - record. It does this by traversing all a, mx, include and redirect statements and combinding them into a single record.
The record is split along 255 character boundaries as to not exceed the TXT record character limit.

In accordance with [RFC 4408 Section 3.1.3](https://tools.ietf.org/html/rfc4408#section-3.1.3) these multiple strings get concatenated into a single string again on the mail server side.

## Usage
```
usage: spfsquash.py [-h] --domain DOMAIN --origin-spf ORIGIN_SPF
                    [--qualifier {+,?,~,-}]

Squash SPF Record

optional arguments:
  -h, --help            show this help message and exit
  --domain DOMAIN       Domain name
  --origin-spf ORIGIN_SPF
                        Origin TXT SPF record to optimize
  --qualifier {+,?,~,-}
                        ALL Qualifier [+?~-]
```

#### Example
```
$ ./spfsquash.py --domain mesosphere.com --origin-spf _origin-spf.mesosphere.com --qualifier -
```

## TODO
Currently the script just outputs the record(s) to STDOUT from where they have to be manually copy'pasted into the DNS zone.
It'd be more useful if the script could automatically update systems like R53 so it can be run via cron.

## Disclaimer
This is experimental code. It works for me but might break for you! Don't trust it blindly. For the first couple of runs validate it's output and if something is wrong open an issue or better yet submit a PR.

