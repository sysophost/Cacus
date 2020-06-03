class Compliance_Issue(object):
    def __init__(self, hostname, name, configured_value, expected_value, info, solution, result):
        self.hostname = hostname
        self.name = name
        self.configured_value = configured_value
        self.expected_value = expected_value
        self.info = info
        self.solution = solution
        self.result = result
