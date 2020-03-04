# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
from mock import patch, MagicMock, call
from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
ELB_RESOURCE_TYPE = 'AWS::ElasticLoadBalancingV2::LoadBalancer'

#############
# Main Code #
#############

MODULE = __import__('ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK')
RULE = MODULE.ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK()

CLIENT_FACTORY = MagicMock()

ELBV2_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'elbv2':
        return ELBV2_CLIENT_MOCK
    if client_name == 'config':
        return CONFIG_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):
    def setUp(self):
        ELBV2_CLIENT_MOCK.reset_mock()
        CONFIG_CLIENT_MOCK.reset_mock()
        self.event = rdklibtest.create_test_scheduled_event()

    def test_scenario1_noElbsInAccount_returnsNotApplicable(self):
        CONFIG_CLIENT_MOCK.list_discovered_resources = MagicMock(return_value={
            'resourceIdentifiers': []
        })
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        rdklibtest.assert_successful_evaluation(self, response, [], 0)

    def test_scenario1_noAlbsInAccount_returnsNotApplicable(self):
        CONFIG_CLIENT_MOCK.list_discovered_resources = MagicMock(return_value={
            'resourceIdentifiers': [{'resourceType': ELB_RESOURCE_TYPE, 'resourceId': 'arn1', 'resourceName': 'load-balancer'}]
        })
        CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(return_value={
            'baseConfigurationItems': [{
                'resourceType': ELB_RESOURCE_TYPE,
                'resourceId': 'arn1',
                'resourceName': 'load-balancer',
                'configuration': '{"type": "network"}'
            }]
        })
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        rdklibtest.assert_successful_evaluation(self, response, [], 0)

    def test_scenario2_allAlbListenersAreSsl_returnsCompliant(self):
        mock_albs_in_config(['arn1'])
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [{'ListenerArn': 'arn1', 'SslPolicy': 'Some_policy_1'}, {'ListenerArn': 'arn2', 'SslPolicy': 'Some_policy_2'}]}
        )
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        rdklibtest.assert_successful_evaluation(self, response, [Evaluation(ComplianceType.COMPLIANT, 'arn1', ELB_RESOURCE_TYPE)], 1)

    def test_scenario3_AlbHasHttpListenerWithNoSSLRedirect_returnsNonCompliant(self):
        mock_albs_in_config(['arn1', 'arn2'])
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'arn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTP'}, 'Type': 'other'}]},
                {'ListenerArn': 'arn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTP'}, 'Type': 'other'}]},
            ]}
        )
        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'other'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'other'}]},
            ]}
        )
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        resp_expected = []
        resp_expected.append(Evaluation(ComplianceType.NON_COMPLIANT, 'arn1', ELB_RESOURCE_TYPE, "HTTP listener rule must have HTTP to HTTPS redirection action configured"))
        resp_expected.append(Evaluation(ComplianceType.NON_COMPLIANT, 'arn2', ELB_RESOURCE_TYPE, "HTTP listener rule must have HTTP to HTTPS redirection action configured"))
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario4_allHttpListenersForAlbHaveSslRedirectionEnabled_returnsCompliant(self):
        mock_albs_in_config(['arn1', 'arn2'])
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'arn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'ListenerArn': 'arn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )

        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        resp_expected = [Evaluation(ComplianceType.COMPLIANT, 'arn1', ELB_RESOURCE_TYPE), Evaluation(ComplianceType.COMPLIANT, 'arn2', ELB_RESOURCE_TYPE)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario4_configServiceCallPagination_returnsCompliant(self):
        CONFIG_CLIENT_MOCK.list_discovered_resources = MagicMock(side_effect=[
            {
                'resourceIdentifiers': [
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn1',
                        'resourceName': 'load-balancer-arn1'
                    },
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn2',
                        'resourceName': 'load-balancer-arn2'
                    }
                ],
                'nextToken': 'abc'
            },
            {
                'resourceIdentifiers': [
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn3',
                        'resourceName': 'load-balancer-arn3'
                    }
                ]
            }
        ])
        CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(side_effect=[
            {
                'baseConfigurationItems': [
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn1',
                        'resourceName': 'load-balancer-arn1',
                        'configuration': '{"type": "application"}'
                    },
                ],
                'unprocessedResourceKeys': [{
                    'resourceType': ELB_RESOURCE_TYPE,
                    'resourceId': 'arn2'
                }]
            },
            {
                'baseConfigurationItems': [
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn2',
                        'resourceName': 'load-balancer-arn2',
                        'configuration': '{"type": "application"}'
                    },
                ]
            },
            {
                'baseConfigurationItems': [
                    {
                        'resourceType': ELB_RESOURCE_TYPE,
                        'resourceId': 'arn3',
                        'resourceName': 'load-balancer-arn3',
                        'configuration': '{"type": "application"}'
                    },
                ]
            }
        ])

        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'arn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'ListenerArn': 'arn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )

        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )
        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, 'arn1', ELB_RESOURCE_TYPE),
            Evaluation(ComplianceType.COMPLIANT, 'arn2', ELB_RESOURCE_TYPE),
            Evaluation(ComplianceType.COMPLIANT, 'arn3', ELB_RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 3)

    def test_scenario4_describeListenersPagination_returnsCompliant(self):
        mock_albs_in_config(['arn1'])

        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(side_effect=[
            {
                'Listeners': [
                    {'ListenerArn': 'listenerArn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                ],
                'NextMarker': 'def'
            },
            {
                'Listeners': [
                    {'ListenerArn': 'listenerArn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]}
                ]
            }
        ])
        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )

        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, 'arn1', ELB_RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

        self.assertEqual(ELBV2_CLIENT_MOCK.mock_calls, [
            call.describe_listeners(LoadBalancerArn='arn1',
                                    PageSize=400),
            call.describe_listeners(LoadBalancerArn='arn1',
                                    PageSize=400,
                                    Marker='def'),
            call.describe_rules(ListenerArn='listenerArn1',
                                PageSize=400),
            call.describe_rules(ListenerArn='listenerArn2',
                                PageSize=400)
        ])

    def test_scenario4_describeRulesPagination_returnsCompliant(self):
        mock_albs_in_config(['arn1'])

        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'listenerArn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]}
            ]}
        )

        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(side_effect=[
            {
                'Rules': [
                    {'RuleArn': 'ruleArn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                ],
                'NextMarker': 'ghi'
            },
            {
                'Rules': [
                    {'RuleArn': 'ruleArn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                ]
            }
        ])

        response = RULE.evaluate_periodic(self.event, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, 'arn1', ELB_RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
        self.assertEqual(ELBV2_CLIENT_MOCK.mock_calls, [
            call.describe_listeners(LoadBalancerArn='arn1',
                                    PageSize=400),
            call.describe_rules(ListenerArn='listenerArn1',
                                PageSize=400),
            call.describe_rules(ListenerArn='listenerArn1',
                                PageSize=400,
                                Marker='ghi')
        ])

def mock_albs_in_config(alb_arns):
    CONFIG_CLIENT_MOCK.list_discovered_resources = MagicMock(return_value={
        'resourceIdentifiers': [
            {
                'resourceType': ELB_RESOURCE_TYPE,
                'resourceId': arn,
                'resourceName': 'load-balancer-' + arn
            } for arn in alb_arns
        ]
    })
    CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(return_value={
        'baseConfigurationItems': [
            {
                'resourceType': ELB_RESOURCE_TYPE,
                'resourceId': arn,
                'resourceName': 'load-balancer-' + arn,
                'configuration': '{"type": "application"}'
            } for arn in alb_arns
        ]
    })
