#!/usr/bin/env python

import argparse

import json
import logging
import sys
import time
import boto3
import botocore
import yaml
import natsort
import traceback

DISABLED_REASON = "Updated via CLI"
DISABLED_REASON_EXCEPTION = "Exception"
DISABLED = "DISABLED"
INITIAL_WAIT_TIME = 0.1  # initial waiting time used between retries in case of a TooManyRequestsException when updating Security Hub

logger = logging.getLogger()


def main(args=None):
    if not args:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description="Disable or Enable security standards controls in AWS Security Hub."
    )
    parser.add_argument(
        "-d",
        "--download",
        help="Get current controls configurations from Security Hub.",
        action="store_true",
    )
    parser.add_argument(
        "-u",
        "--upload",
        help="Upload Security Hub controls configurations as defined in UPLOAD file.",
    )
    parser.add_argument(
        "--json",
        help="Use json as file format (instead of yaml) when downloading current controls configurations from Security Hub. Only effective when used in conjunction with -d/--download",
        action="store_true",
    )
    parser.add_argument(
        "--profile", help="Use a specific profile from your credential file."
    )
    parser.add_argument(
        "--dynamodb", help="Optional - Specify DynamoDB table name storing exceptions."
    )
    parser.add_argument(
        "--max-retries",
        help="Maximal amount of retries in case of a TooManyRequestsException when updating Security Hub controls. (default: infinity)",
        default=-1,
        type=int,
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        help="Debugging information",
        action="count",
    )
    args = parser.parse_args(args)

    if args.verbosity == 1:
        logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    elif args.verbosity == 2:
        logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.WARNING)

    if args.download:
        download_controls(args.json, profile_name=args.profile, dynamodb=args.dynamodb)
    elif args.upload:
        upload_controls(
            args.upload,
            max_retries=args.max_retries,
            profile_name=args.profile,
            dynamodb=args.dynamodb,
        )
    else:
        logger.error("Use either -u or -d!")
        parser.print_help()


# Business logic below


class ControlsLocal:
    """ This class contains the dictionary of security standards and controls as they are saved in the local file """

    def __init__(self, controls=None):
        if not controls:
            controls = dict()
        self.controls = controls

    def add_new_control(self, control):
        """ Adding a new control. As input, take a control as returned by security_hub_client.describe_standards_controls() """
        standard = control["StandardsControlArn"].split("/")[-4]

        if standard not in self.controls or not self.controls[standard]:
            self.controls[standard] = dict()

        self.controls[standard][control["ControlId"]] = dict()
        self.controls[standard][control["ControlId"]]["Title"] = control["Title"]
        # self.controls[standard][control["ControlId"]]["Description"] = control["Description"]
        self.controls[standard][control["ControlId"]]["ControlStatus"] = control[
            "ControlStatus"
        ]

        try:
            self.controls[standard][control["ControlId"]]["DisabledReason"] = control[
                "DisabledReason"
            ]
        except KeyError:
            self.controls[standard][control["ControlId"]]["DisabledReason"] = ""

    def sort_controls(self):
        """ Sorting the list of controls per security standard to make it more useful for the human reader. """
        for standard in self.controls:
            controls_list_ids = list(self.controls[standard].keys())

            controls_old = self.controls[standard].copy()
            self.controls[standard] = dict()
            for control_id in natsort.versorted(controls_list_ids):
                self.controls[standard][control_id] = controls_old[control_id]

    def add_control_exception(self, control, exception):
        """ Adding an exception to a control """
        standard = control["StandardsControlArn"].split("/")[-4]
        disabled = "Disabled"
        enabled = "Enabled"
        for key in (disabled, enabled):
            if len(exception[key]) > 0:
                self.controls[standard][control["ControlId"]][key] = exception[key]
            if key == disabled:
                # Add DisabledReason if not yet existing
                if (
                    self.controls[standard][control["ControlId"]]["DisabledReason"]
                    == ""
                    and exception["DisabledReason"]
                ):
                    self.controls[standard][control["ControlId"]][
                        "DisabledReason"
                    ] = exception["DisabledReason"]

    def exception_exists(self, controlid):
        """ Check if an exception is defined for this control """
        for standard in self.controls:
            for control in self.controls[standard]:
                if control == controlid:
                    if "Disabled" in self.controls[standard][controlid].keys():
                        return True
                    if "Enabled" in self.controls[standard][controlid].keys():
                        return True
                    return False
        return False


def download_controls(JSON, profile_name=None, dynamodb=None):
    """
    Downloads the security standard controls from Security Hub and saves it into a file
    """
    session = boto3.session.Session(profile_name=profile_name)
    security_hub_client = session.client("securityhub")
    dynamo_db_client = session.client("dynamodb")

    # Download current security standards controls from Security Hub
    controls_local = get_controls(security_hub_client, dynamo_db_client, dynamodb)

    # Print to std.out
    controls_local.sort_controls()
    if JSON:
        print(json.dumps(controls_local.controls, indent=4))
    else:
        print(yaml.dump(controls_local.controls, sort_keys=False))


def get_controls(security_hub_client, dynamo_db_client, dynamodb):
    """
    Returns the ControlsLocal object, enrichted with the security standards control status from Security Hub
    """
    controls_local = ControlsLocal()
    controls_online = get_controls_online(security_hub_client)

    # Exceptions
    if dynamodb:
        exceptions_online = get_exceptions_online(dynamo_db_client, dynamodb)
    else:
        exceptions_online = dict()

    for standard in controls_online:
        logger.debug(standard)
        for control in controls_online[standard]["Controls"]:
            logger.debug(control)
            controls_local.add_new_control(control)
            if control["ControlId"] in exceptions_online.keys():
                controls_local.add_control_exception(
                    control, exceptions_online[control["ControlId"]]
                )
    return controls_local


def get_exceptions_online(client, dynamodb):
    """
    Returns exceptions
    """
    try:
        response = client.scan(TableName=str(dynamodb))
    except (
        botocore.exceptions.ParamValidationError,
        client.exceptions.ResourceNotFoundException,
    ):
        logger.error(
            "DynamoDB table %s not found. Make sure the specified DynamoDB table exists in your account.",
            str(dynamodb),
        )
        sys.exit(1)
    return convert_exceptions(response)


def convert_exceptions(response):
    """
    Convert exceptions from DynamoDB into simpler dictionary format
    """
    exceptions = dict()
    for control in response["Items"]:
        exceptions[control["ControlId"]["S"]] = dict()

        try:
            exceptions[control["ControlId"]["S"]]["Disabled"] = [
                entry["S"] for entry in control["Disabled"]["L"]
            ]
        except KeyError:
            logger.debug('%s: No "Disabled" exceptions', control["ControlId"]["S"])
            exceptions[control["ControlId"]["S"]]["Disabled"] = []

        try:
            exceptions[control["ControlId"]["S"]]["Enabled"] = [
                entry["S"] for entry in control["Enabled"]["L"]
            ]
        except KeyError:
            logger.debug('%s: No "Enabled" exceptions', control["ControlId"]["S"])
            exceptions[control["ControlId"]["S"]]["Enabled"] = []

        try:
            if control["DisabledReason"]["S"] != "":
                exceptions[control["ControlId"]["S"]]["DisabledReason"] = control[
                    "DisabledReason"
                ]["S"]
            else:
                logger.debug(
                    '%s: No "DisabledReason". Replace by "%s"',
                    control["ControlId"]["S"],
                    DISABLED_REASON_EXCEPTION,
                )
                exceptions[control["ControlId"]["S"]][
                    "DisabledReason"
                ] = DISABLED_REASON_EXCEPTION
        except KeyError:
            logger.debug(
                '%s: No "DisabledReason". Replace by "%s"',
                control["ControlId"]["S"],
                DISABLED_REASON_EXCEPTION,
            )
            exceptions[control["ControlId"]["S"]][
                "DisabledReason"
            ] = DISABLED_REASON_EXCEPTION

    return exceptions


def get_controls_online(client):
    """
    Downloads security standard controls via the provided client.
    Return: dictionary of security standards, each containing a list of controls including all the information given via client.describe_standards_controls()
    """
    logger.debug("Enter get_controls_online")
    controls_online = dict()
    enabled_standards = client.get_enabled_standards()

    for standard in enabled_standards["StandardsSubscriptions"]:
        standard_name = standard["StandardsArn"].split("/")[-3]
        logger.debug(standard_name)
        if standard_name not in controls_online:
            # initialize new standard
            controls_online[standard_name] = dict()
        controls_online[standard_name] = client.describe_standards_controls(
            StandardsSubscriptionArn=standard["StandardsSubscriptionArn"]
        )

    logger.debug("controls_online = %s", str(controls_online))
    logger.debug("Leave get_controls_online")

    return controls_online


def upload_controls(local_file, max_retries, profile_name=None, dynamodb=None):
    """
    Loads the local_file into the object controls_local.
    It updates the Security Hub controls accordingly to controls_local by using the update_controls() subroutine.
    Finally, the local file is updated if new controls were discovered in Security Hub during update_controls()
    """
    config = botocore.config.Config(retries={"max_attempts": 24, "mode": "standard"})
    session = boto3.session.Session(profile_name=profile_name)
    security_hub_client = session.client("securityhub", config=config)
    dynamodb_client = session.client("dynamodb", config=config)

    # Load local controls into controls_local
    JSON = False
    try:
        with open(local_file, "r") as f:
            controls_local = ControlsLocal(json.loads(f.read()))
        JSON = True
    except json.decoder.JSONDecodeError:
        with open(local_file, "r") as f:
            controls_local = ControlsLocal(yaml.safe_load(f))

    # Update Security Hub controls accordingly to controls_local
    print("Start updating security standard controls...")
    controls_local, controls_local_changed = update_controls(
        controls_local, security_hub_client, max_retries
    )
    print("Security standard controls updated.")

    # Update local file if new controls were discovered in Security Hub
    if controls_local_changed:
        update_local_file(controls_local, local_file, JSON)

    # Update exceptions in DynamoDB table according to controls_local
    if dynamodb:
        print("Start updating exceptions in DynamoDB table...")
        update_exceptions(controls_local, dynamodb_client, dynamodb)
        print("Exceptions in DynamoDB table updated.")


def update_exceptions(controls_local, client, dynamodb):
    """
    Update exceptions in DynamoDB table as set in controls_local object. Scan the table first. Then update each item individually, if it does not match the information in controls_local.
    """
    exceptions_online = get_exceptions_online(client, dynamodb)
    for standard in controls_local.controls:
        local_control = controls_local.controls[standard]
        for control in local_control:
            if (
                controls_local.exception_exists(control)
                and control in exceptions_online
            ):
                # exception locally defined - check if update is needed
                if exceptions_match(exceptions_online[control], local_control[control]):
                    # no update needed
                    continue
                print(control + ": Update exceptions in DynamoDB table.")
                client.put_item(
                    Item=make_item(control, local_control[control]), TableName=dynamodb
                )
            elif (
                controls_local.exception_exists(control)
                and control not in exceptions_online
            ):
                # exception locally defined but not yet in DynamoDB - new entry
                print(control + ": Create exceptions in DynamoDB table.")
                client.put_item(
                    Item=make_item(control, local_control[control]), TableName=dynamodb
                )
            elif (
                not controls_local.exception_exists(control)
                and control in exceptions_online
            ):
                # no exception locally but entry in DynamoDB - remove entry from DynamoDB
                print(control + ": Delete exceptions in DynamoDB table.")
                client.delete_item(
                    Key={"ControlId": {"S": control}}, TableName=dynamodb
                )


def make_item(control, local_control):
    """
    create Item to be sent in the dynamodb_client.put_item() api call
    """
    item = dict()
    item["ControlId"] = {"S": control}
    try:
        item["Disabled"] = {
            "L": [{"S": str(account_id)} for account_id in local_control["Disabled"]]
        }
        if local_control["DisabledReason"] != "":
            item["DisabledReason"] = {"S": local_control["DisabledReason"]}
        else:
            item["DisabledReason"] = {"S": DISABLED_REASON_EXCEPTION}
    except KeyError:
        logger.info("%s: No Disabled exception", control)
    try:
        item["Enabled"] = {
            "L": [{"S": str(account_id)} for account_id in local_control["Enabled"]]
        }
    except KeyError:
        logger.info("%s: No Enabled exception.", control)
    return item


def exceptions_match(exceptions_control, local_control):
    """
    exceptions_control: Item from DynamoDB table
    local_control: Entry from local file
    Return True if exceptions in local_control match the item in DynamoDB table -> Update not needed. Else return False and update is needed.
    """
    no_exceptions_found = dict()
    for key in ("Disabled", "Enabled"):

        no_exceptions_found[key] = False

        # Sanity check
        if key in local_control.keys():
            if not isinstance(local_control[key], list):
                logger.error("%s must be an array.", key)
                sys.exit(1)

        if key in exceptions_control.keys() and key in local_control.keys():
            if not set(exceptions_control[key]).intersection(
                set(str(x) for x in local_control[key])
            ) == set(exceptions_control[key]):
                # Exceptions lists do not match
                return False
        elif key in exceptions_control.keys():
            if len(exceptions_control[key]) > 0:
                # Exception online but not local
                return False
        elif key in local_control.keys():
            if len(local_control[key]) > 0:
                # Exception local but not online
                return False
        else:
            # No exceptions found
            no_exceptions_found[key] = True

    if all(no_exceptions_found[key] for key in ("Disabled", "Enabled")):
        # No exceptions found at all. No need to check DisabledReason
        return True

    key = "DisabledReason"
    if "Disabled" in local_control and len(local_control["Disabled"]) > 0:
        # Only check DisabledReason if Disabled exceptions are defined

        # Sanity check
        if key in local_control.keys():
            if not isinstance(local_control[key], str):
                logger.error("%s must be a string.", key)
                sys.exit(1)

        if key in exceptions_control.keys() and key in local_control.keys():
            if exceptions_control[key] != local_control[key] and not (local_control[key] == "" and exceptions_control[key] == DISABLED_REASON_EXCEPTION):
                # DisabledReason do not match and need to updated, since local_control's DisabledReason is not empty
                return False
        elif key in local_control.keys():
            if local_control[key] != "":
                # If DisabledReason is explicitely specified locally, change also in DynamoDB
                return False
    return True


def update_controls(controls_local, client, max_retries):
    """
    Updates the security standards controls in Security Hub as they are set in the object controls_local object
    Return:
        controls_local - modified if new security standards or controls were added to Security Hub and were not reflected yet in the controls_local
        controls_local_changed - True if new security standards or controls were added to Security Hub and were not reflected yet in the controls_local
    """
    controls_local_changed = False
    controls_online = get_controls_online(client)

    # Update standards online to reflect setup in local file
    standards_updated = update_standards_online(client, controls_local, controls_online)
    if standards_updated:
        logger.info("Fetch controls again.")
        controls_online = get_controls_online(client)

    for standard in controls_online:
        logger.debug(standard)

        for online_control in controls_online[standard]["Controls"]:

            logger.debug(online_control)

            # Check if control from controls_online is present in local file and add it if it is missing
            try:
                local_control = controls_local.controls[standard]
                # control_status_local = controls_local.controls[standard][
                control_status_local = local_control[online_control["ControlId"]][
                    "ControlStatus"
                ]
            except (KeyError, TypeError):
                logger.warning(
                    "Control %s:%s does not exist in local file. Local file is being updated ...",
                    standard,
                    online_control["ControlId"],
                )
                controls_local.add_new_control(online_control)
                controls_local_changed = True
                continue

            # Update online controls if needed
            control_status_online = online_control["ControlStatus"]
            if control_status_online != control_status_local:
                try_update_control_status(
                    online_control,
                    control_status_local,
                    local_control,
                    client,
                    max_retries,
                )

    return controls_local, controls_local_changed


def try_update_control_status(
    online_control, control_status_local, local_control, client, max_retries
):
    """
    Exponential backoff in case of a "TooManyRequestsException" ClientError with maximum amount of retries defined in max_retries parameter
    """

    print(online_control["ControlId"], ": Update to", control_status_local)

    # exponential backoff - Repeat update_standards_control until it is successful or max_retries is reached
    successful = False
    wait = INITIAL_WAIT_TIME
    retries = 0

    while not successful:
        try:
            update_control_status(
                local_control, control_status_local, online_control, client
            )
            successful = True
            print(online_control["ControlId"], ": Done")

        except botocore.exceptions.ClientError as err:
            response = err.response
            logger.info(
                "Failed to update control: %s", response.get("Error", {}).get("Message")
            )
            if (
                response
                and response.get("Error", {}).get("Code") == "TooManyRequestsException"
            ):
                if max_retries > -1:
                    # retry until max_retries is reached
                    if retries < max_retries:
                        retries += 1
                    else:
                        logger.error(
                            "TooManyRequestsException. Try to increase max_retries!"
                        )
                        sys.exit()
                wait = sleep_and_increase_wait(wait, max_retries - retries + 1)
            else:
                raise err


def update_control_status(local_control, control_status_local, online_control, client):
    """
    Updates the Security Hub control as specified in the local file
    """

    try:
        if control_status_local == DISABLED:
            # DISABLE control
            # disabled_reason = controls_local.controls[standard][
            disabled_reason = local_control[online_control["ControlId"]]["DisabledReason"]

            if not disabled_reason:
                disabled_reason = DISABLED_REASON

            client.update_standards_control(
                StandardsControlArn=online_control["StandardsControlArn"],
                ControlStatus=control_status_local,
                DisabledReason=disabled_reason,
            )

        else:
            # ENABLE control
            client.update_standards_control(
                StandardsControlArn=online_control["StandardsControlArn"],
                ControlStatus=control_status_local,
            )
    except client.exceptions.InvalidInputException as error:
        logger.error("%s: %s", online_control["ControlId"], error)
        logger.debug("%s", traceback.format_exc())
        sys.exit(1)


def sleep_and_increase_wait(wait, retries_left):
    """
    Sleeps for `wait` seconds and doubles the wait time for next retry
    """
    logger.info("Sleep for %s seconds...", str(wait))
    time.sleep(wait)
    wait *= 2  # exponentially increase waiting time
    if retries_left > 1:
        logger.info("Repeat %i more times.", retries_left)
    elif retries_left == 1:
        logger.info("Repeat %i more time.", retries_left)
    return wait


def update_local_file(controls_local, local_file, JSON):
    """
    Updates the local file with the content of controls_local
    """
    controls_local.sort_controls()

    with open(local_file, "w") as f:
        if JSON:
            json.dump(controls_local.controls, f, indent=4)
        else:
            yaml.dump(controls_local.controls, f, sort_keys=False)


def update_standards_online(client, controls_local, controls_online):
    """
    Update security standards to reflect state in local file
    """
    standards = client.describe_standards()["Standards"]
    standard_to_be_enabled = []
    standard_to_be_disabled = []

    for standard in standards:
        standard_name = standard["StandardsArn"].split("/")[-3]
        if (
            standard_name in controls_local.controls.keys()
            and standard_name not in controls_online.keys()
        ):
            # Standard is not yet enabled but should be
            standard_to_be_enabled.append({"StandardsArn": standard["StandardsArn"]})
        if (
            standard_name not in controls_local.controls.keys()
            and standard_name in controls_online.keys()
        ):
            # Standard is enabled but should not be
            standard_to_be_disabled.append(
                "/".join(
                    controls_online[standard_name]["Controls"][0][
                        "StandardsControlArn"
                    ].split("/")[:-1]
                ).replace(":control/", ":standards/")
            )

    standards_changed = False

    if len(standard_to_be_enabled) > 0:
        # enable standard
        logger.info("Enable standards: %s", str(standard_to_be_enabled))
        client.batch_enable_standards(
            StandardsSubscriptionRequests=standard_to_be_enabled
        )
        ready = False
        while not ready:
            response = client.get_enabled_standards()
            subscription_statuses = [
                subscription["StandardsStatus"]
                for subscription in response["StandardsSubscriptions"]
            ]
            ready = all(
                (status in ("READY", "INCOMPLETE") for status in subscription_statuses)
            )
            if not ready:
                if "FAILED" in subscription_statuses:
                    logger.error(
                        "Standard could not be enabled: %s",
                        str(response["StandardsSubscriptions"]),
                    )
                    sys.exit(1)
            logger.info("Wait until standards are enabled...")
            time.sleep(1)
        if "INCOMPLETE" in subscription_statuses:
            logger.warning(
                "Standard could not be enabled completely. Some controls may not be available: %s",
                str(response["StandardsSubscriptions"]),
            )
        logger.info("Standards enabled")
        standards_changed = True

    if len(standard_to_be_disabled) > 0:
        # disable standard
        logger.info("Disable standards: %s", str(standard_to_be_disabled))
        client.batch_disable_standards(
            StandardsSubscriptionArns=standard_to_be_disabled
        )
        ready = False
        while not ready:
            response = client.get_enabled_standards()
            subscription_statuses = [
                subscription["StandardsStatus"]
                for subscription in response["StandardsSubscriptions"]
            ]
            ready = all(
                (status in ("READY", "INCOMPLETE") for status in subscription_statuses)
            )
            if not ready:
                if "FAILED" in subscription_statuses:
                    logger.error(
                        "Standard could not be disabled: %s",
                        str(response["StandardsSubscriptions"]),
                    )
                    sys.exit(1)
            logger.info("Wait until standards are disabled...")
            time.sleep(1)
        if "INCOMPLETE" in subscription_statuses:
            logger.warning(
                "Standard could not be enabled completely. Some controls may not be available: %s",
                str(response["StandardsSubscriptions"]),
            )
        logger.info("Standards disabled")
        standards_changed = True
    return standards_changed
