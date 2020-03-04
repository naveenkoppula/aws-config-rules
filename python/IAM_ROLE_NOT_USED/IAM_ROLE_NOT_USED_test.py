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

from datetime import datetime, timezone, timedelta

from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType, InvalidParametersError
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::IAM::Role'

#############
# Main Code #
#############

MODULE = __import__('IAM_ROLE_NOT_USED')
RULE = MODULE.IAM_ROLE_NOT_USED()

CLIENT_FACTORY = MagicMock()

#example for mocking S3 API calls
IAM_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT = MagicMock()


def mock_get_client(service, *args, **kwargs):
    if service == 'iam':
        return IAM_CLIENT_MOCK
    if service == 'config':
        return CONFIG_CLIENT
    raise Exception("Attempting to create an unknown client")


@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    def test_compliance(self):
        rule_parameters = {"DaysBeforeUnused": "90"}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        input_event = rdklibtest.create_test_scheduled_event(rule_parameters_json=rule_parameters)
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"config-rule"}']}
        IAM_CLIENT_MOCK.get_role.return_value = {"Role":{"RoleLastUsed": {"LastUsedDate": datetime.now(timezone.utc)}}}
        response = RULE.evaluate_periodic(input_event, CLIENT_FACTORY, rule_parameters)
        resp_expected = [Evaluation(ComplianceType.COMPLIANT, 'config-rule', RESOURCE_TYPE)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_non_compliance(self):
        rule_parameters = {"DaysBeforeUnused":"90"}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        input_event = rdklibtest.create_test_scheduled_event(rule_parameters_json=rule_parameters)
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"AWS-CodePipeline-Service"}']}
        IAM_CLIENT_MOCK.get_role.return_value = {"Role":{"RoleLastUsed": {"LastUsedDate": datetime.now(timezone.utc) - timedelta(days=100)}}}
        response = RULE.evaluate_periodic(input_event, CLIENT_FACTORY, rule_parameters)
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT, 'AWS-CodePipeline-Service', RESOURCE_TYPE)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_invalid_params_strings(self):
        rule_parameters = {"DaysBeforeUnused": "sdfsdf"}
        with self.assertRaises(InvalidParametersError) as context:
            RULE.evaluate_parameters(rule_parameters)
        self.assertIn('The parameter "DaysBeforeUnused" must be a integer', str(context.exception))

    def test_invalid_params_negative(self):
        rule_parameters = {"DaysBeforeUnused": "-10"}
        with self.assertRaises(InvalidParametersError) as context:
            RULE.evaluate_parameters(rule_parameters)
        self.assertIn('The parameter "DaysBeforeUnused" must be greater than or equal to 0', str(context.exception))
