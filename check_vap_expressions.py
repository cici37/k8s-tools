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
    pathToValidations: List[str]
    pathToAuditAnnotations: List[str]
    pathToVariables: List[str]


INDEX_WILDCARD = "*"


RESOURCE_KINDS_TO_CHECK = [
    ResourceKindInfo(
        kind = "ValidatingAdmissionPolicy",
        pathToName = ["metadata", "name"],
        pathToMatchConditions = ["spec", "matchConditions", INDEX_WILDCARD],
        pathToValidations = ["spec", "validations", INDEX_WILDCARD],
        pathToAuditAnnotations = ["spec", "auditAnnotations", INDEX_WILDCARD],
        pathToVariables = ["spec", "variables", INDEX_WILDCARD]
    ),
]


SUBSTRING = "authorizer."


THRESHOLD_COUNT_PERCALL = 3
THRESHOLD_COUNT_PERRES = 29
THRESHOLD_COUNT_PERMC = 9

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
                        validations = []
                        audit_annotations = []
                        variables = []
                        try:
                            match_conditions = _subobjects_at_path(item, resourceKind.pathToMatchConditions)
                        except ValueError:
                            pass
                        try:
                            validations = _subobjects_at_path(item, resourceKind.pathToValidations)
                        except ValueError:
                            pass
                        try:
                            audit_annotations = _subobjects_at_path(item, resourceKind.pathToAuditAnnotations)
                        except ValueError:
                            pass
                        try:
                            variables = _subobjects_at_path(item, resourceKind.pathToVariables)
                        except ValueError:
                            pass

                        # Create a map from variables.name to variables.expression
                        variables_map = {var["name"]: var["expression"] for var in variables}

                        total_count_mc = 0  # Initialize total count for SUBSTRING in matchConditions
                        total_count_v = 0  # Initialize total count for SUBSTRING in validations
                        total_count_aa = 0  # Initialize total count for SUBSTRING in auditAnnotation

                        for match_condition in match_conditions:
                            condition_expression: str = match_condition["expression"]
                            # Count how many times SUBSTRING appears in the expression of the match condition.
                            count = condition_expression.count(SUBSTRING)
                            total_count_mc += count
                            if count >= THRESHOLD_COUNT_PERCALL:
                                print(f"Resource {resourceKind.kind} {name} has excessive usage of auth checks in match"
                                      f" condition: {condition_expression}",
                                      file=sys.stderr)

                            if total_count_mc >= THRESHOLD_COUNT_PERMC:
                                print(
                                    f"Resource {resourceKind.kind} {name} has excessive total usage of auth checks in match"
                                    f" conditions: {total_count_mc} occurrences of '{SUBSTRING}'",
                                    file=sys.stderr)
                        for validation in validations:
                            validation_expression: str = validation["expression"]
                            # Replace variable names with their expressions
                            for var_name, var_expression in variables_map.items():
                                validation_expression = validation_expression.replace(var_name, var_expression)
                            # Count how many times SUBSTRING appears in the expression of the match condition.
                            count = validation_expression.count(SUBSTRING)
                            total_count_v += count
                            if count >= THRESHOLD_COUNT_PERCALL:
                                print(
                                    f"Resource {resourceKind.kind} {name} has excessive usage of auth checks in validation"
                                    f" expression: {validation["expression"]}",
                                    file=sys.stderr)

                            if total_count_v >= THRESHOLD_COUNT_PERRES:
                                print(
                                    f"Resource {resourceKind.kind} {name} has excessive total usage of auth checks in validation"
                                    f" expression: {total_count_v} occurrences of '{SUBSTRING}'",
                                    file=sys.stderr)

                        for annotation in audit_annotations:
                            annotation_expression: str = annotation["valueExpression"]
                            # Replace variable names with their expressions
                            for var_name, var_expression in variables_map.items():
                                annotation_expression = annotation_expression.replace(var_name, var_expression)
                            # Count how many times SUBSTRING appears in the expression of the match condition.
                            count = annotation_expression.count(SUBSTRING)
                            total_count_aa += count
                            if count >= THRESHOLD_COUNT_PERCALL:
                                print(
                                    f"Resource {resourceKind.kind} {name} has excessive usage of auth checks in audit annotation"
                                    f" expression: {annotation["valueExpression"]}",
                                    file=sys.stderr)

                            if total_count_aa >= THRESHOLD_COUNT_PERRES:
                                print(
                                    f"Resource {resourceKind.kind} {name} has excessive total usage of auth checks in audit annotation"
                                    f" expression: {total_count_aa} occurrences of '{SUBSTRING}'",
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
