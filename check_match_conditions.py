#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check match conditions of validating admission policies for excessive usage of authorized resources.
"""

__author__ = "Cici Huang"

import json
import subprocess
import sys
from collections import defaultdict
from typing import NamedTuple, List, Dict


class ResourceKindInfo(NamedTuple):
    kind: str
    pathToName: List[str]
    pathToMatchConditions: List[str]


INDEX_WILDCARD = "*"


RESOURCE_KINDS_TO_CHECK = [
    ResourceKindInfo(
        kind = "ValidatingAdmissionPolicy",
        pathToName = ["metadata", "name"],
        pathToMatchConditions = ["spec", "matchConditions", INDEX_WILDCARD]
    ),
    ResourceKindInfo(
        kind = "ValidatingWebhookConfiguration",
        pathToName = ["metadata", "name"],
        pathToMatchConditions = ["webhooks", INDEX_WILDCARD, "matchConditions", INDEX_WILDCARD]
    ),
    ResourceKindInfo(
        kind = "MutatingWebhookConfiguration",
        pathToName = ["metadata", "name"],
        pathToMatchConditions = ["webhooks", INDEX_WILDCARD, "matchConditions", INDEX_WILDCARD]
    ),
]


SUBSTRING = "authorizer."


THRESHOLD_COUNT = 3


def _subobjects_at_path(obj, path):
    if not path:
        return [obj]

    first_component = path[0]
    rest_of_path = path[1:]
    if first_component == INDEX_WILDCARD:
        if not isinstance(obj, list):
            raise ValueError(f"Expected list to parse INDEX_WILDCARD \"{INDEX_WILDCARD}\" but got a non-list object: "
                             f"{obj}")
        subobjects = []
        for item in obj:
            subobjects.extend(_subobjects_at_path(item, rest_of_path))
        return subobjects
    else:
        if not isinstance(obj, dict) or first_component not in obj:
            raise ValueError(f"Expected dict with key \"{first_component}\" but got: {obj}")
        return _subobjects_at_path(obj[first_component], rest_of_path)


def _main():
    summary_stats : Dict[str, int] = defaultdict(int)
    for resourceKind in RESOURCE_KINDS_TO_CHECK:
        kubectl_command = ["kubectl", "get", resourceKind.kind, "-o", "json"]

        try:
            kubectl_output = subprocess.check_output(kubectl_command, text=True)

            try:
                kubectl_output_obj = json.loads(kubectl_output)

                for item in kubectl_output_obj["items"]:
                    try:
                        name = _subobjects_at_path(item, resourceKind.pathToName)[0]
                        match_conditions = []
                        try:
                            match_conditions = _subobjects_at_path(item, resourceKind.pathToMatchConditions)
                        except ValueError:
                            pass
                        for match_condition in match_conditions:
                            condition_expression: str = match_condition["expression"]
                            # Count how many times SUBSTRING appears in the expression of the match condition.
                            if condition_expression.count(SUBSTRING) >= THRESHOLD_COUNT:
                                print(f"Resource {resourceKind.kind} {name} has excessive usage of auth checks in match"
                                      f" condition: {condition_expression}",
                                      file=sys.stderr)

                        summary_stats[resourceKind.kind] += 1
                    except (ValueError, KeyError, IndexError) as e:
                        print(f"Error parsing {resourceKind.kind} item: {e}. Item: {item}",
                              file=sys.stderr)

            except json.JSONDecodeError as e:
                print(
                    f"Error decoding JSON output from kubectl command {kubectl_command}: {e}. Output: {kubectl_output}",
                    file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error running kubectl command {kubectl_command}: {e}", file=sys.stderr)

    print("Summary stats:")
    for resourceKind in RESOURCE_KINDS_TO_CHECK:
        print(f"{resourceKind.kind}: {summary_stats[resourceKind.kind]} resource(s) found and checked.")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    _main()
