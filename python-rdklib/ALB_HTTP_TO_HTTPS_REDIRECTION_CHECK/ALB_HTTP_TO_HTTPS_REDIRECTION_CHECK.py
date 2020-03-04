# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
'''
Rule Name:
  ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK
Description:
  Checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule
  is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancer do not have HTTP to HTTPS redirection
  configured.
Trigger:
  Periodic
Reports on:
  AWS::ElasticLoadBalancingV2::LoadBalancer
Rule Parameters:
  None
Scenarios:
  Scenario: 1
     Given: No Application Load Balancer is present
      Then: Return NOT_APPLICABLE
  Scenario: 2
     Given: There is at least 1 Application Load Balancer
       And: Application Load Balancer has only HTTPS listener(s)
      Then: Return COMPLIANT
  Scenario: 3
     Given: There is at least 1 Application Load Balancer
       And: Application Load Balancer has one or more HTTP listeners configured
       And: At least one HTTP listener rule does not have HTTP to HTTPS redirection action configured
      Then: Return NON_COMPLIANT
  Scenario: 4
     Given: There is at least 1 Application Load Balancer
       And: Application Load Balancer has one or more HTTP listeners configured
       And: All HTTP listener rules have HTTP to HTTPS redirection action configured
      Then: Return COMPLIANT
'''
import json
from time import sleep

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

DEFAULT_RESOURCE_TYPE = 'AWS::ElasticLoadBalancingV2::LoadBalancer'
DEFAULT_THROTTLE_PERIOD = 0.1
CONFIG_PAGE_SIZE = 100
ELB_PAGE_SIZE = 400

class ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        alb_client = client_factory.build_client("elbv2")
        config_client = client_factory.build_client("config")
        all_elbv2 = get_all_albs(config_client)
        for elb in all_elbv2:
            alb_all_listeners = get_all_listeners(alb_client, elb)
            is_alb_compliant = all(is_listener_compliant(listener, alb_client) for listener in alb_all_listeners)
            if is_alb_compliant:
                evaluations.append(
                    Evaluation(ComplianceType.COMPLIANT, elb, DEFAULT_RESOURCE_TYPE))
            else:
                evaluations.append(
                    Evaluation(ComplianceType.NON_COMPLIANT, elb, DEFAULT_RESOURCE_TYPE,
                               "HTTP listener rule must have HTTP to HTTPS redirection action configured"))
        return evaluations

def get_all_albs(config_client):
    albs, next_token = list_albs(config_client)

    while next_token:
        sleep(DEFAULT_THROTTLE_PERIOD)
        more_albs, next_token = list_albs(config_client, next_token)

        albs += more_albs

    return [alb['resourceId'] for alb in albs]

def list_albs(config_client, next_token=None):
    args = {
        'resourceType': DEFAULT_RESOURCE_TYPE,
        'limit': CONFIG_PAGE_SIZE,
        'includeDeletedResources': False
    }
    if next_token:
        args['nextToken'] = next_token

    list_resources_response = config_client.list_discovered_resources(**args)
    albs = filter_to_only_albs(config_client, list_resources_response['resourceIdentifiers'])

    return albs, list_resources_response.get('nextToken')

def filter_to_only_albs(config_client, all_elbv2):
    resource_keys = [{'resourceType': elb['resourceType'], 'resourceId': elb['resourceId']} for elb in all_elbv2]

    items = []
    while resource_keys:
        response = config_client.batch_get_resource_config(resourceKeys=resource_keys)
        items += [elb for elb in response['baseConfigurationItems'] if is_alb(elb)]

        resource_keys = response.get('unprocessedResourceKeys')
        if resource_keys:
            sleep(DEFAULT_THROTTLE_PERIOD)

    return items

def is_alb(resource):
    resource_configuration = json.loads(resource['configuration'])

    return resource_configuration.get('type') == 'application'

def get_all_listeners(client, elbv2_arn):
    resp = client.describe_listeners(LoadBalancerArn=elbv2_arn, PageSize=ELB_PAGE_SIZE)
    items = []
    while resp:
        items += resp['Listeners']

        if 'NextMarker' in resp:
            sleep(DEFAULT_THROTTLE_PERIOD)
            resp = client.describe_listeners(LoadBalancerArn=elbv2_arn, PageSize=ELB_PAGE_SIZE, Marker=resp['NextMarker'])
        else:
            resp = None
    return items

def get_all_listener_rules(client, listener_arn):
    resp = client.describe_rules(ListenerArn=listener_arn, PageSize=ELB_PAGE_SIZE)
    items = []
    while resp:
        items += resp['Rules']

        if 'NextMarker' in resp:
            sleep(DEFAULT_THROTTLE_PERIOD)
            resp = client.describe_rules(ListenerArn=listener_arn, PageSize=ELB_PAGE_SIZE, Marker=resp['NextMarker'])
        else:
            resp = None
    return items

def is_listener_compliant(listener, alb_client):
    if is_https_listener(listener):
        return True

    listener_rules = get_all_listener_rules(alb_client, listener['ListenerArn'])
    return all(is_listener_rule_compliant(listener_rule) for listener_rule in listener_rules)

def is_listener_rule_compliant(listener_rule):
    return all(is_https_redirect_action(action) for action in listener_rule['Actions'])

def is_https_redirect_action(action):
    return action['Type'] == 'redirect' and action['RedirectConfig']['Protocol'] == 'HTTPS'

def is_https_listener(listener):
    return 'SslPolicy' in listener

################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
