import logging
from xml.etree import ElementTree as ET

from models import compliance_issue as ci


def parse_hosts(report: ET.Element) -> list:
    """
    Extract hosts from the supplied Report element

    Arguments:
        report {ET.Element} -- Report element extracted from the document root

    Returns:
        list -- List of hosts extracted from the supplied Report element
    """

    logging.info(f"[i] Parsing report: {report.get('name')}")
    report_hosts = report.findall('./ReportHost')
    return report_hosts


def parse_compliance(report_host: ET.Element, ns: dict) -> list:
    """
    Extract compliance issues from the supplied ReportHost element

    Arguments:
        report_host {ET.Element} -- ReportHost element extracted from the current Report element
        ns {dict} -- Node namespace aliases

    Returns:
        list -- List of compliance issue objects for the given ReportHost
    """

    host_properties = report_host.find('HostProperties')
    report_items = report_host.findall('ReportItem')

    compliance_issues = list(filter(lambda x: x.attrib['pluginFamily'] == 'Policy Compliance', report_items))
    parsed_issues = list()

    for item in compliance_issues:
        hostname = report_host.get('name')
        name = getattr(item.find('cm:compliance-check-name', ns), 'text', 'n/a')
        configured_value = getattr(item.find('cm:compliance-actual-value', ns), 'text', 'n/a')
        expected_value = getattr(item.find('cm:compliance-policy-value', ns), 'text', 'n/a')
        expected_value = expected_value.replace('expect: ', '')
        info = getattr(item.find('cm:compliance-info', ns), 'text', 'n/a')
        result = getattr(item.find('cm:compliance-result', ns), 'text', 'n/a')

        # overwrite solution with n/a if result is PASSED
        if result == 'PASSED':
            solution = 'n/a'
        else:
            solution = getattr(item.find('cm:compliance-solution', ns), 'text', 'n/a')

        issue = ci.Compliance_Issue(hostname, name, configured_value, expected_value, info, solution, result)
        parsed_issues.append(issue)

    return parsed_issues
