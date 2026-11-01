# Name: Zack Zavadskiy
# Student ID: 041268014

import yaml
import json
import sys

import xml.etree.ElementTree as ET


class AuditError(Exception):
    """Custom exception for invalid audit configuration"""
    pass


class Device:
    """Represents a network device from the inventory"""

    def __init__(self, xml_device):
        """Extracting device information from an XML element"""
        self.id = xml_device.get("id")
        self.role = xml_device.get("role")
        self.os = xml_device.get("os")
        self.interfaces = xml_device.findall("interface")

        owner = xml_device.findtext("owner")
        self.owner = owner.strip() if owner is not None else ""

    def has_owner(self):
        """Check whether the device has a non-empty owner"""
        return self.owner != ""


# OS versions policy check
def compare_versions(found, required):
    """Return True if the found OS version is older than required."""
    found_OS = [int(part) for part in found.split(".")]

    required_OS = [int(part) for part in required.split(".")]

    if len(found_OS) < len(required_OS):
        highest = len(required_OS)
    else:
        highest = len(found_OS)

    found_OS += [0] * (highest - len(found_OS))  # add missing elements as many times as needed

    return found_OS < required_OS


def load_inputs(xml_file, policy_file):
    """Load the XML inventory and YAML policy, validating the inputs."""
    try:
        tree = ET.parse(xml_file)

        with open(policy_file, "r", encoding="utf-8") as f:
            loaded_policy = yaml.safe_load(f)

    except FileNotFoundError as e:
        raise AuditError(f"File not found: {e.filename}") from e

    except ET.ParseError as e:
        raise AuditError(f"Invalid XML in {xml_file}: {e}") from e

    except yaml.YAMLError as e:
        raise AuditError(f"Invalid YAML in {policy_file}: {e}") from e

    policy = {} if loaded_policy is None else loaded_policy

    if not isinstance(policy, dict):
        raise AuditError("Policy must be a YAML dictionary.")

    return tree.getroot(), policy


def audit_inventory(root, policy):
    """Audit all devices against the supplied policy and build a report."""
    roles = {}
    violations = []
    compliant = []

    interfaces = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    total_devices = 0
    skipped_devices = 0


    # main loop
    for xml_device in root.findall("device"):  # searching the whole root
        device = Device(xml_device)

        # skipping devices without an id, increment count
        if device.id is None:
            skipped_devices += 1

        else:
            role = device.role

            if role in roles:
                roles[role] += 1
            else:
                roles[role] = 1

            # OS check
            min_os = policy.get("min_os")

            if min_os is not None:
                if role in min_os:
                    required = min_os[role]  # gets OS required for the exact device role
                    found = device.os

                    if found is not None:
                        if compare_versions(str(found), str(required)):  # True means found is older than required
                            #without quotes will real as float in YAML
                            violations.append({
                                "device": device.id,
                                "type": "os_outdated",
                                "found": found,
                                "required": required
                            })
                else:
                    violations.append({
                        "device": device.id,
                        "type": "unknown_role",
                        "role": role
                    })

            down_count = 0  # policy 2 counter

            # check every interface status in each device / inventory
            for interface in device.interfaces:
                if interface.get("status") in ("up", "down"):
                    interfaces[interface.get("status")] += 1  # increment the status it's in

                    if interface.get("status") == "down":
                        down_count += 1  # counter for policy #2

                else:
                    interfaces["other"] += 1

            # policy 2: max down interfaces
            if policy.get("max_down_interfaces") is not None:
                if down_count > policy.get("max_down_interfaces"):
                    violations.append({
                        "device": device.id,
                        "down": down_count,
                        "type": "too_many_down"
                    })

            total_devices += 1

            # policy 1: missing owner
            if policy.get("require_owner", False):  # checks whether the policy requires an owner
                if not device.has_owner():
                    violations.append({
                        "device": device.id,
                        "type": "missing_owner"
                    })

            # compliant
            has_violation = False

            for v in violations:
                if v["device"] == device.id:  # if device is found in violations list
                    has_violation = True

            if not has_violation:
                compliant.append(device.id)

    # report dict
    report = {
        "site": root.get("site"),
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant)  # sorted puts it in alphabetical order
    }

    return report


#program starts here

def write_report(report):
    """Write the audit report to audit.json."""
    with open("audit.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def print_summary(report):
    """short summary of the audit results"""
    print(f"site: {report['site']}")
    print(f"total_devices: {report['total_devices']}")
    print(f"skipped_devices: {report['skipped_devices']}")

    role_summary = ", ".join(
        f"{role} {count}" for role, count in report["roles"].items()
    )
    print(f"roles: {role_summary}")

    interface_summary = (
        f"up {report['interfaces']['up']}, "
        f"down {report['interfaces']['down']}, "
        f"other {report['interfaces']['other']}"
    )
    print(f"interfaces: {interface_summary}")

    print("violations:")
    for violation in report["violations"]:
        details = ", ".join(
            f"{key}: {value}" for key, value in violation.items()
        )
        print(f"  {{{details}}}")

    print(f"compliant: {report['compliant']}")


def main():
    """Run the fleet compliance audit."""
    # Check the number of arguments
    if len(sys.argv) != 3:
        print(f"usage: python {sys.argv[0]} DEVICES.xml POLICY.yaml")
        return 2

    # Store the filenames
    xml_file = sys.argv[1]
    policy_file = sys.argv[2]

    try:
        root, policy = load_inputs(xml_file, policy_file)

    except AuditError as e:
        print(f"Error: {e}")
        return 1

    report = audit_inventory(root, policy)

    write_report(report)
    print_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())