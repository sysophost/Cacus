import logging
import math
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


def aggregate_issues(report_issues: list, nopadding: bool) -> list:
    """
    Aggregate issues by host

    Args:
        report_issues (list): List of compliance issues to aggregate

    Returns:
        list: List of issues aggregated by host
    """

    aggregated_issues = list()

    unique_issue_titles = set(i.name for i in report_issues)
    for issue in unique_issue_titles:
        issue_passed = list(filter(lambda x: x.name == issue and x.result == 'PASSED', report_issues))
        if issue_passed:
            pass_host_count = len(list(i.hostname for i in issue_passed))
            pass_config = '\n'.join(i.configured_value for i in issue_passed)
            if nopadding:
                padding = 1
            else:
                padding = math.ceil(pass_config.count('\n') / pass_host_count)
            pass_hostnames = ('\n' * padding).join(i.hostname for i in issue_passed)
            pass_issue = ci.Compliance_Issue(pass_hostnames, issue_passed[0].name, pass_config, issue_passed[0].expected_value, issue_passed[0].info, issue_passed[0].solution, 'PASSED')
            aggregated_issues.append(pass_issue)

        issue_failed = list(filter(lambda x: x.name == issue and x.result == 'FAILED', report_issues))
        if issue_failed:
            fail_host_count = len(list(i.hostname for i in issue_failed))
            fail_config = '\n'.join(i.configured_value for i in issue_failed)
            if nopadding:
                padding = 1
            else:
                padding = math.ceil(fail_config.count('\n') / 2)
            fail_hostnames = ('\n' * padding).join(i.hostname for i in issue_failed)
            fail_issue = ci.Compliance_Issue(fail_hostnames, issue_failed[0].name, fail_config, issue_failed[0].expected_value, issue_failed[0].info, issue_failed[0].solution, 'FAILED')
            aggregated_issues.append(fail_issue)

    return aggregated_issues
