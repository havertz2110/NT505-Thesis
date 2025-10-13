import os
import json

# OWASP Top 10 2021 mapping based on the data provided
owasp_mapping = {
    "A01:2021 - Broken Access Control": [
        22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377,
        402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706,
        862, 863, 913, 922, 1275
    ],
    "A02:2021 - Cryptographic Failures": [
        261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
        331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916
    ],
    "A03:2021 - Injection": [
        20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97,
        98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917
    ],
    "A04:2021 - Insecure Design": [
        73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
        430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650,
        653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173
    ],
    "A05:2021 - Security Misconfiguration": [
        2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776,
        942, 1004, 1032, 1174
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        937, 1035, 1104
    ],
    "A07:2021 - Identification and Authentication Failures": [
        255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384,
        521, 613, 620, 640, 798, 940, 1216
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        345, 353, 426, 494, 502, 565, 784, 829, 830, 915
    ],
    "A09:2021 - Security Logging and Monitoring Failures": [
        117, 223, 532, 778
    ],
    "A10:2021 - Server-Side Request Forgery (SSRF)": [
        918
    ]
}

# Get all testcase folders
testcases_dir = r"D:\GitHub\UIT-Final\dataset\juliet-dynamic-master\testcases"
folders = [f for f in os.listdir(testcases_dir) if os.path.isdir(os.path.join(testcases_dir, f))]

# Create reverse mapping: CWE number -> OWASP category
cwe_to_owasp = {}
for owasp_cat, cwe_list in owasp_mapping.items():
    for cwe_num in cwe_list:
        if cwe_num not in cwe_to_owasp:
            cwe_to_owasp[cwe_num] = []
        cwe_to_owasp[cwe_num].append(owasp_cat)

# Categorize folders
categorized = {}
uncategorized = []

for folder in folders:
    # Extract CWE number from folder name (e.g., CWE78_OS_Command_Injection -> 78)
    if folder.startswith("CWE"):
        cwe_num_str = folder.split("_")[0].replace("CWE", "")
        try:
            cwe_num = int(cwe_num_str)
            if cwe_num in cwe_to_owasp:
                for owasp_cat in cwe_to_owasp[cwe_num]:
                    if owasp_cat not in categorized:
                        categorized[owasp_cat] = []
                    categorized[owasp_cat].append(folder)
            else:
                uncategorized.append(folder)
        except ValueError:
            uncategorized.append(folder)
    else:
        uncategorized.append(folder)

# Save results to categorize folder
output_dir = r"D:\GitHub\UIT-Final\categorize"
os.makedirs(output_dir, exist_ok=True)

# Save categorized results
for owasp_cat, folders in sorted(categorized.items()):
    # Create short name (e.g., A01, A02, etc.)
    short_name = owasp_cat.split(":")[0].replace(":", "")
    filename = f"{output_dir}/{short_name}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"{owasp_cat}\n")
        f.write("=" * 80 + "\n\n")
        for folder in sorted(folders):
            f.write(f"{folder}\n")

    print(f"Saved {len(folders)} testcases to {short_name}.txt")

# Save uncategorized results
if uncategorized:
    with open(f"{output_dir}/uncategorized.txt", "w", encoding="utf-8") as f:
        f.write("Uncategorized CWE Testcases\n")
        f.write("=" * 80 + "\n\n")
        for folder in sorted(uncategorized):
            f.write(f"{folder}\n")
    print(f"Saved {len(uncategorized)} uncategorized testcases")

# Save summary
with open(f"{output_dir}/summary.txt", "w", encoding="utf-8") as f:
    f.write("OWASP Top 10 2021 Categorization Summary\n")
    f.write("=" * 80 + "\n\n")

    for owasp_cat, folders in sorted(categorized.items()):
        short_name = owasp_cat.split(":")[0]
        f.write(f"{short_name}: {len(folders)} testcases\n")

    f.write(f"\nUncategorized: {len(uncategorized)} testcases\n")
    f.write(f"Total: {len(folders)} testcases\n")

print(f"\nSummary saved to summary.txt")
print(f"Total testcases: {sum(len(v) for v in categorized.values()) + len(uncategorized)}")
