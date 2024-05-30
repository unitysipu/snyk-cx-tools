import getopt
import logging
import os
import sys
from datetime import datetime

import coloredlogs
import snyk
import snyk.errors
from yaspin import yaspin

FORMAT = "[%(asctime)s] [%(process)d:%(threadName)s] [%(levelname)s] [%(name)s.%(module)s.%(funcName)s:%(lineno)d] %(message)s"

logger = logging.getLogger(__name__)
coloredlogs.install(level="DEBUG", fmt=FORMAT)


helpString = """
This script will allow you to deactivate or delete projects in bulk based on a set of filters.
set your SNYK_TOKEN as an environment variable to use this script.

Usage: SNYK_TOKEN=your_token python snyk-bulk-delete.py [options]

--help: Returns this page

--force: By default this script will perform a dry run, add this flag to actually apply changes

--delete: By default this script will deactivate projects, add this flag to delete active projects instead

--delete-non-active-projects: By default this script will deactivate projects, add this flag to delete non-active projects instead
(if this flag is present only non-active projects will be deleted)

--origins: Defines origin of projects to delete (github, github-enterprise, github-cloud-app...)

--orgs: A set of orgs upon which to perform delete, be sure to use org slug instead of org display name (use ! for all orgs)

--sca-types: Defines types of projects to delete (deb, linux, dockerfile, rpm, apk, npm, sast ...)

--products: Defines which Snyk feature related projects to delete
             examples: sast container iac opensource

--product_excludes: Defines product/s types of projects to exclude from deletion

--delete-empty-orgs: This will delete all orgs that do not have any projects in them
    * Please replace spaces with dashes(-) when entering orgs
    * If entering multiple values use the following format: "value-1 value-2 value-3"

--after: Only delete projects that were created after a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)

--before : Only delete projects that were created before  a certain date time (in ISO 8601 format, i.e 2023-09-01T00:00:00.000Z)

--ignore-keys: An array of key's, if any of these key's are present in a project name then that project will not be targeted for deletion/deactivation
"""


if "--help" in sys.argv:
    print(helpString)
    sys.exit(2)


# get all user orgs and verify snyk API token
snyk_token = os.getenv("SNYK_TOKEN", "")
if not snyk_token:
    logger.error("💥 Please set your SNYK_TOKEN as an environment variable")
    print(helpString)
    sys.exit(1)


try:
    client = snyk.SnykClient(token=snyk_token)
    userOrgs = client.organizations.all() or []
    logger.info("Found organizations: %s", len(userOrgs))
except snyk.errors.SnykHTTPError as err:
    logger.error(
        "💥 Ran into an error while fetching account details, please check your API token: %s",
        vars(err),
    )
    print(helpString)
    sys.exit(1)


def is_date_between(curr_date_str, before_date_str, after_date_str):
    # Parse the current date string into a datetime object
    curr_date = datetime.strptime(curr_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    # Parse the before date string into a datetime object if it's not empty
    if before_date_str:
        before_date = datetime.strptime(before_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        before_date = None

    # Parse the after date string into a datetime object if it's not empty
    if after_date_str:
        after_date = datetime.strptime(after_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        after_date = None

    # Check if the current date is between the before and after dates
    if before_date and after_date:
        return (
            curr_date <= before_date  # pylint: disable=chained-comparison
            and curr_date >= after_date
        )
    if before_date:
        return curr_date <= before_date
    if after_date:
        return curr_date >= after_date

    # If both before and after dates are empty, return True
    return True


def convertProjectTypeToProduct(inputType: str) -> str:
    containerTypes = ["deb", "linux", "dockerfile", "rpm", "apk"]
    iacTypes = [
        "k8sconfig",
        "helmconfig",
        "terraformconfig",
        "armconfig",
        "cloudformationconfig",
    ]
    codeTypes = ["sast"]
    open_source_types = [
        "cocoapods",
        "composer",
        "cpp",
        "golangdep",
        "gomodules",
        "govendor",
        "gradle",
        "hex",
        "maven",
        "npm",
        "nuget",
        "paket",
        "pip",
        "pipenv",
        "poetry",
        "rubygems",
        "sbt",
        "swift",
        "yarn",
    ]

    if inputType in containerTypes:
        return "container"
    if inputType in iacTypes:
        return "iac"
    if inputType in codeTypes:
        return "sast"
    if inputType in open_source_types:
        return "opensource"

    logger.warning("Unknown project type: %s", inputType)
    return "unknown"


def main(argv):  # pylint: disable=too-many-statements
    inputOrgs = []
    products = []
    scaTypes = []
    origins = []
    product_excludes = []
    deleteorgs = False
    dryrun = True
    deactivate = True
    deleteNonActive = False
    beforeDate = ""
    afterDate = ""
    ignoreKeys = []

    # valid input arguments declared here
    try:
        opts, _ = getopt.getopt(
            argv,
            "hofd",
            [
                "help",
                "orgs=",
                "sca-types=",
                "products=",
                "product_excludes=",
                "origins=",
                "ignore-keys=",
                "before=",
                "after=",
                "force",
                "delete-empty-orgs",
                "delete",
                "delete-non-active-projects",
            ],
        )
    except getopt.GetoptError:
        logger.error("Error parsing input, please check your syntax: %s", argv)
        sys.exit(2)

    # process input
    logger.debug(opts)
    for opt, arg in opts:
        if opt == "--help":
            print(helpString)
            sys.exit(2)
        if opt == "--orgs":
            if arg == "!":
                inputOrgs = [org.slug for org in userOrgs]
            else:
                inputOrgs = arg.split()
        if opt == "--sca-types":
            scaTypes = [scaType.lower() for scaType in arg.split()]
        if opt == "--products":
            products = [product.lower() for product in arg.split()]
        if opt == "--product_excludes":
            product_excludes = [product.lower() for product in arg.split()]
        if opt == "--origins":
            origins = [origin.lower() for origin in arg.split()]
        if opt == "--delete-empty-orgs":
            deleteorgs = True
        if opt == "--force":
            dryrun = False
        if opt == "--delete":
            deactivate = False
        if opt == "--delete-non-active-projects":
            deactivate = False
            deleteNonActive = True
        if opt == "--before":
            beforeDate = arg
        if opt == "--after":
            afterDate = arg
        if opt == "--ignore-keys":
            ignoreKeys = [key.lower() for key in arg.split()]

    # error handling if no filters declared
    logger.debug(
        "Filters: sca-types: %s, products: %s, origins: %s, product_excludes: %s",
        scaTypes,
        products,
        origins,
        product_excludes,
    )

    filtersEmpty = (
        len(scaTypes) == 0
        and len(products) == 0
        and len(product_excludes) == 0
        and len(origins) == 0
    )
    if filtersEmpty and not deleteorgs:
        logger.debug("Empty params %s:", filtersEmpty)
        logger.error(
            "No settings entered, define one of: sca-types, products, product_excludes, origins"
        )
        print(helpString)
        sys.exit(2)

    # error handling if no orgs declared
    if len(inputOrgs) == 0:
        print("No orgs to process entered, exiting")
        print(helpString)

    # print dryrun message
    if dryrun:
        print(
            "\033[93mTHIS IS A DRY RUN, NOTHING WILL BE DELETED! USE --FORCE TO APPLY ACTIONS\u001b[0m"
        )

    results = {
        "projects": {"deactivated": [], "deleted": [], "failed": [], "skipped": []},
        "orgs": {"deleted": [], "skipped": []},
    }
    # delete functionality
    for currOrg in userOrgs:  # pylint: disable=too-many-nested-blocks

        # if curr org is in list of orgs to process
        if currOrg.slug not in inputOrgs:
            logger.debug("Skipping organization: %s not in %s", currOrg.slug, inputOrgs)
            continue

        logger.info(
            "Processing organization: %s",
            currOrg.slug,
        )

        # cycle through all projects in current org and delete projects that match filter
        for currProject in currOrg.projects.all():

            # variables which determine whether project matches criteria to delete, if criteria is empty they will be defined as true
            scaTypeMatch = False
            originMatch = False
            productMatch = False
            dateMatch = False
            nameMatch = True
            isActive = currProject.isMonitored

            # dateMatch validation
            try:
                dateMatch = is_date_between(currProject.created, beforeDate, afterDate)
            except ValueError as exc:
                logger.error(
                    "Error processing before/after datetimes, please check your format %s",
                    exc,
                )
                sys.exit(2)

            # nameMatch validation
            for key in ignoreKeys:
                if key in currProject.name:
                    nameMatch = False

            # if scatypes are not declared or curr project type matches filter criteria then return true
            if len(scaTypes) != 0:
                if currProject.type in scaTypes:
                    scaTypeMatch = True
            else:
                scaTypeMatch = True

            # if origintypes are not declared or curr project origin matches filter criteria then return true
            if len(origins) != 0:
                if currProject.origin in origins:
                    originMatch = True
            else:
                originMatch = True

            # if producttypes are not declared or curr project product matches filter criteria then return true
            currProjectProductType = convertProjectTypeToProduct(currProject.type)

            if (currProjectProductType in products) or (
                currProjectProductType not in product_excludes
            ):
                productMatch = True

            # Guard clause to avoid complex conditions below
            if not (
                scaTypeMatch
                and originMatch
                and productMatch
                and dateMatch
                and nameMatch
                and not filtersEmpty
            ):
                logger.debug(
                    "Skipping unmatched project: %s, Type: %s, Origin: %s, Product: %s",
                    currProject.name,
                    currProject.type,
                    currProject.origin,
                    currProjectProductType,
                )
                results["projects"]["skipped"].append(currProject)
                continue

            # delete active project if filters are met
            if isActive and not deleteNonActive:
                currProjectDetails = f"Origin: {currProject.origin}, Type: {currProject.type}, Product: {currProjectProductType}"
                action = "Deactivating" if deactivate else "Deleting"
                spinner = yaspin(
                    text=f"{action}\033[1;32m {currProject.name}", color="yellow"
                )
                spinner.write(
                    f"\u001b[0m    Processing project: \u001b[34m{currProjectDetails}\u001b[0m, Status Below👇"
                )
                spinner.start()
                try:
                    if not deactivate:
                        if not dryrun:
                            currProject.delete()
                        results["projects"]["deleted"].append(currProject)
                    else:
                        if not dryrun:
                            currProject.deactivate()
                        results["projects"]["deactivated"].append(currProject)
                    spinner.ok("✅ ")
                except Exception as e:
                    spinner.fail(f"💥 {e}")
                    results["projects"]["failed"].append(currProject)
                finally:
                    spinner.stop()

            # delete non-active project if filters are met
            if not isActive and deleteNonActive:
                currProjectDetails = f"Origin: {currProject.origin}, Type: {currProject.type}, Product: {currProjectProductType}"
                spinner = yaspin(
                    text=f"Deleting\033[1;32m {currProject.name}", color="yellow"
                )
                spinner.write(
                    f"\u001b[0m    Processing project: \u001b[34m{currProjectDetails}\u001b[0m, Status Below👇"
                )
                spinner.start()
                try:
                    if not dryrun:
                        currProject.delete()
                        results["projects"]["deleted"].append(currProject)
                    spinner.ok("✅ ")
                except Exception as e:
                    spinner.fail(f"💥 {e}")
                    results["projects"]["failed"].append(currProject)
                finally:
                    spinner.stop()

        # if org is empty and --delete-empty-org flag is on
        if len(currOrg.projects.all()) == 0 and deleteorgs:

            spinner = yaspin(
                text="Deleting\033[1;32m {}\u001b[0m since it is an empty organization".format(
                    currOrg.name
                ),
                color="yellow",
            )
            spinner.start()
            try:
                if not dryrun:
                    client.delete(f"org/{currOrg.id}")
                results["orgs"]["deleted"].append(currOrg)
                spinner.ok("✅ ")
            except Exception as e:
                spinner.fail(f"💥 {e}")
                results["orgs"]["failed"].append(currOrg)
            finally:
                spinner.stop()

    if dryrun:
        print("\033[93mDRY RUN COMPLETE NOTHING DELETED")

    for i_type in results:  # pylint: disable=consider-using-dict-items
        for action in results[i_type]:
            logger.info(
                "%s - %s: %s",
                i_type.capitalize(),
                action.capitalize(),
                len(results[i_type][action]),
            )


main(sys.argv[1:])
