import re
from pathlib import Path

REMOVE_UUID = True


def split_firewall_objects(lines, section_name):
    objects = []
    current = []
    inside_section = False
    depth = 0

    for line in lines:
        stripped = line.strip().lower()

        if stripped == section_name.lower():
            inside_section = True
            continue

        if inside_section and stripped == "end" and depth == 0:
            break

        if not inside_section:
            continue

        if stripped.startswith("edit ") and depth == 0:
            current = [line]
            continue

        if current:
            current.append(line)

            if stripped.startswith("config "):
                depth += 1
            elif stripped == "end" and depth > 0:
                depth -= 1
            elif stripped == "next" and depth == 0:
                objects.append(current)
                current = []

    return objects


def extract_reference_dynamic_mapping(obj, source_fw, source_vdom):
    source_edit = f'edit "{source_fw}"-"{source_vdom}"'.lower()

    output = []
    inside_dynamic_mapping = False
    inside_source_mapping = False

    for line in obj:
        stripped = line.strip()
        lower = stripped.lower()

        if lower == "config dynamic_mapping":
            inside_dynamic_mapping = True
            continue

        if inside_dynamic_mapping and lower == source_edit:
            inside_source_mapping = True
            output.append(line)
            continue

        if inside_source_mapping:
            output.append(line)

            if lower == "next":
                break

    return output if output else None


def rewrite_mapping(mapping_lines, source_fw, source_vdom, target_fw, target_vdom):
    source_pattern = re.compile(
        rf'^(\s*)edit\s+"{re.escape(source_fw)}"-"{re.escape(source_vdom)}"\s*$',
        re.IGNORECASE
    )

    uuid_pattern = re.compile(r'^\s*set\s+uuid\s+', re.IGNORECASE)

    rewritten = []

    for line in mapping_lines:
        if REMOVE_UUID and uuid_pattern.match(line):
            continue

        match = source_pattern.match(line)

        if match:
            indent = match.group(1)
            rewritten.append(f'{indent}edit "{target_fw}"-"{target_vdom}"\n')
        else:
            rewritten.append(line)

    return rewritten


def get_object_edit_line(obj):
    for line in obj:
        if line.strip().lower().startswith("edit "):
            return line
    return None


def main():
    source_fw = input("Reference firewall name: ").strip()
    target_fw = input("New target firewall name: ").strip()

    source_vdom = input("Reference VDOM [root]: ").strip() or "root"
    target_vdom = input("Target VDOM [root]: ").strip() or "root"

    input_file = input("FortiManager export file [fortimanager_export.txt]: ").strip()
    if not input_file:
        input_file = "fortimanager_export.txt"

    output_file = input("Output file [generated_vip_dynamic_mapping.txt]: ").strip()
    if not output_file:
        output_file = "generated_vip_dynamic_mapping.txt"

    input_path = Path(input_file)

    if not input_path.exists():
        print(f"ERROR: File not found: {input_file}")
        return

    lines = input_path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines(keepends=True)

    vip_objects = split_firewall_objects(lines, "config firewall vip")

    output = ["config firewall vip\n"]
    matched = 0

    for obj in vip_objects:
        object_edit_line = get_object_edit_line(obj)

        mapping = extract_reference_dynamic_mapping(
            obj,
            source_fw,
            source_vdom
        )

        if not object_edit_line or not mapping:
            continue

        matched += 1

        output.append(object_edit_line)
        output.append("    config dynamic_mapping\n")
        output.extend(
            rewrite_mapping(
                mapping,
                source_fw,
                source_vdom,
                target_fw,
                target_vdom
            )
        )
        output.append("    end\n")
        output.append("next\n")

    output.append("end\n")

    Path(output_file).write_text(
        "".join(output),
        encoding="utf-8"
    )

    print()
    print("Done.")
    print(f"Total VIP objects found : {len(vip_objects)}")
    print(f"Matched VIP objects     : {matched}")
    print(f"Source mapping          : {source_fw}-{source_vdom}")
    print(f"Target mapping          : {target_fw}-{target_vdom}")
    print(f"Output file             : {output_file}")


if __name__ == "__main__":
    main()