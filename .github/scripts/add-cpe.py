
import sys
import xml.etree.ElementTree as ET

if len(sys.argv) != 3:
    print("Usage: python add-cpe.py <bom.xml> <cpe-mapping.xml>")
    sys.exit(1)

sbom_path = sys.argv[1]
mapping_path = sys.argv[2]

# Read CPE mapping
mapping_tree = ET.parse(mapping_path)
mapping_root = mapping_tree.getroot()

mapping = {}

for item in mapping_root.findall("component"):
    name = item.get("name")
    vendor = item.get("vendor")
    product = item.get("product")

    if name and vendor and product:
        mapping[name] = {
            "vendor": vendor,
            "product": product
        }

# Read CycloneDX SBOM
tree = ET.parse(sbom_path)
root = tree.getroot()

# Detect CycloneDX XML namespace
namespace = (
    root.tag.split("}")[0][1:]
    if "}" in root.tag
    else ""
)

prefix = f"{{{namespace}}}" if namespace else ""

if namespace:
    ET.register_namespace("", namespace)

count = 0

# Process components
for component in root.findall(
    f"./{prefix}components/{prefix}component"
):
    name = component.findtext(f"{prefix}name")
    version = component.findtext(f"{prefix}version")

    if name not in mapping or not version:
        continue

    entry = mapping[name]

    cpe_value = (
        f"cpe:2.3:a:"
        f"{entry['vendor']}:"
        f"{entry['product']}:"
        f"{version}:*:*:*:*:*:*:*"
    )

    cpe_element = component.find(f"{prefix}cpe")

    if cpe_element is None:
        # Insert CPE before PURL, if present
        cpe_element = ET.Element(f"{prefix}cpe")

        purl_element = component.find(f"{prefix}purl")

        if purl_element is not None:
            index = list(component).index(purl_element)
            component.insert(index, cpe_element)
        else:
            component.append(cpe_element)

    cpe_element.text = cpe_value

    print(f"CPE added: {name} {version} -> {cpe_value}")
    count += 1

# Save updated SBOM
tree.write(
    sbom_path,
    encoding="utf-8",
    xml_declaration=True
)

print(f"\nTotal CPE mappings applied: {count}")
