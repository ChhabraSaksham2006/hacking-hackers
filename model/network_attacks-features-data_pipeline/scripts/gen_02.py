import pandas as pd

criteria = [
    "1. Authenticity & Provenance",
    "2. Original Source Organization",
    "3. Number of Recorded Flows",
    "4. Number of Telemetry Features",
    "5. Feature Calculation Quality",
    "6. Feature Semantics & Network Coverage",
    "7. Timestamp Availability",
    "8. Chronological Ordering Integrity",
    "9. Flow & Session Identity Tracking",
    "10. Target Host Identity",
    "11. Overall Attack Diversity",
    "12. Multi-Stage Infiltration Scenario",
    "13. Brute Force (SSH/FTP/Web)",
    "14. Botnet (C2 Communication)",
    "15. DoS (Hulk, GoldenEye, Slowloris)",
    "16. DDoS (LOIC, HOIC)",
    "17. Web Attacks (SQLi, XSS, BruteForce)",
    "18. Reconnaissance & PortScan",
    "19. Benign Traffic Volume & Ratio",
    "20. Missing Values Presence",
    "21. Infinite Values (Div by Zero)",
    "22. Duplicate Records Handling",
    "23. Known Ground-Truth Labeling Errors",
    "24. Known Feature Extraction Errors",
    "25. Preprocessing & Cleaning Status",
    "26. Temporal Forecasting Suitability",
    "27. Multi-Step Horizon Suitability (t+K)",
    "28. MITRE ATT&CK Mapping Suitability",
    "29. Computational & Storage Practicality",
    "30. Reproducibility & Open Access",
    "31. Documentation & Academic Citations",
    "32. Open Source License / Terms",
    "33. Overall Scientific Credibility"
]

rows = [
    # Cand A: CSE-CIC-IDS2018 Official
    ("A", "Official CSE-CIC-IDS2018", [
        "Verified Authentic", "UNB & CSE Canada (2018)", "16,233,002", "80", "Good (Needs NaN/Inf Clean)",
        "Layer 3, 4, and 7 Flow Telemetry", "Explicit Timestamp (dd/MM/yyyy HH:mm:ss)", "Monotonic Chronological Days",
        "Dst Port, Protocol, Duration, Flow Rates", "Victim IPs in PCAP/Documentation", "Very High (14 Attack Types)",
        "Yes (Feb 28 & Mar 01 Multi-Hour)", "Yes (FTP & SSH Patator)", "Yes (ARES Botnet)", "Yes (Hulk, GoldenEye, Slowloris)",
        "Yes (LOIC-HTTP, LOIC-UDP, HOIC)", "Yes (SQLi, XSS, Brute Force)", "Yes (Embedded in Infiltration/Bot)",
        "~13.4M Benign Flows (~83%)", "2,277 in Flow Byts/s (Fixed by Imputer)", "5,371 in Rates (Fixed by Clamping)",
        "Legitimate Bursts (Retained for Rate)", "Minor (~1% in Web, Fixable)", "Handled by Fixed Imputer",
        "Raw CSVs Require Parquet Conversion", "EXCELLENT (True Timeline)", "EXCELLENT (Continuous Days)",
        "HIGH (Direct Mapping to 9 Tactics)", "Manageable (~8GB CSV -> ~1.8GB Parquet)", "100% Open Access on AWS",
        "Comprehensive (Whitepaper & UNB)", "Open for Academic & Research Use", "GOLD STANDARD BENCHMARK"
    ]),
    # Cand B: NF-CSE-CIC-IDS2018-v2
    ("B", "NF-CSE-CIC-IDS2018-v2 (UQ)", [
        "Verified Authentic", "University of Queensland (2022)", "18,893,708", "43 NetFlow + Attack + Label", "Pre-Cleaned & Imputed",
        "Strict NetFlow v9 RFC Standards", "Flow Summary Durations (Timestamps Stripped)", "Preserved Flow Sequence",
        "Full 4-Tuple (IPs, Ports, Proto)", "Internal Subnet Mapping", "High (6 Grouped Attack Families)",
        "Yes (116,361 Flows Grouped)", "Yes (120,912 Flows)", "Yes (143,097 Flows)", "Yes (Grouped in DoS/DDoS)",
        "Yes (1,874,269 Flows)", "Yes (3,502 Flows)", "Embedded in Scans",
        "16,635,567 Flows (88.05%)", "0 (Pre-cleaned)", "0 (Pre-cleaned)",
        "Deduplicated across Identifiers", "Corrected to NetFlow Ground Truth", "Minimal (Standard NetFlow Parser)",
        "Pre-Formatted Clean Parquet", "Moderate (Requires Sequential Re-Indexing)", "Moderate (Feature-Space Rollout)",
        "Good (Technique Mapping by Family)", "Highly Optimized (~1.2 GB Parquet)", "Open via UQ eSpace & Kaggle",
        "Peer-Reviewed (IEEE TNSM / MoNA)", "Creative Commons Attribution", "VERY HIGH (Standard NetFlow)"
    ]),
    # Cand C: CSE-CIC-IDS2018 Improved (DistriNet)
    ("C", "CSE-CIC-IDS2018 Improved (DistriNet)", [
        "Verified Authentic", "DistriNet / KU Leuven (2021)", "16,233,002 (Patched)", "80 (Cleaned CICFlowMeter)", "Scientifically Corrected",
        "Layer 3, 4, 7 Flow Telemetry", "Cleaned Datetime Timestamps", "Strict Chronological",
        "Dst Port, Protocol, Flow Dynamics", "Documented Testbed Topology", "Very High (14 Attack Types)",
        "Yes (Cleaned Infiltration Labels)", "Yes (Patator Attacks)", "Yes (ARES C2)", "Yes (Cleaned Hulk, Slowloris)",
        "Yes (LOIC, HOIC)", "Yes (Cleaned Web Attack Labels)", "Yes (Scan Flows)",
        "~83% Benign Traffic", "Zero (Handled via Corrected Parser)", "Zero (Handled via Corrected Parser)",
        "Preserved with Timestamp Order", "Corrected ~7.5% Mislabeled Flows", "Patched CICFlowMeter Engine",
        "Fully Cleaned & Audited", "EXCELLENT (True Timeline + Fixed Labels)", "EXCELLENT",
        "VERY HIGH (Cleanest Ground Truth)", "Moderate (~8 GB Processed)", "Open Research Scripts & Data",
        "Top-Tier Cybersecurity Research", "Open Academic License", "HIGHEST GROUND-TRUTH ACCURACY"
    ]),
    # Cand D: Kaggle chethuhn (CIC-IDS2017)
    ("D", "Kaggle chethuhn (CIC-IDS2017)", [
        "Verified Authentic (CIC-IDS2017)", "ISCX / UNB (Uploaded by Chethuhn)", "2,830,743", "79 + Label", "Raw Uncleaned",
        "Layer 3, 4 Flow Telemetry", "Timestamp String in CSV", "Destroyed if Shuffled; Retrievable in Raw",
        "Dst Port, Protocol, Flow Rates", "Unknown (IPs Stripped in CSV)", "High (15 Attack Classes)",
        "Yes (36 Flows on Thursday)", "Yes (FTP & SSH Patator)", "Yes (ARES Botnet)", "Yes (Hulk, GoldenEye, Slowloris)",
        "Yes (DDoS LOIC)", "Yes (Brute Force, XSS, SQLi)", "Yes (158,930 PortScan Flows)",
        "~2.27M Benign Flows (~80%)", "2,880 in Flow Byts/s", "Infs in Packet/Byte Rates",
        "288k Duplicate Vectors", "Encoding Bugs on Web Attacks", "Known CICFlowMeter-V1 Bug",
        "Raw Uncleaned State", "Moderate (Only if Chronologically Restored)", "Moderate",
        "High (Standard 2017 Classes)", "Very Light (~350 MB Compressed)", "Open Access on Kaggle",
        "Heavily Cited Benchmark", "Open Dataset", "VALUABLE FOR EXTERNAL VALIDATION"
    ]),
    # Cand E: Multi-Dataset CIC Collection
    ("E", "Multi-Dataset CIC Collection (17/18/19)", [
        "Mixed Benchmarks", "UNB Multi-Year Archives", ">30,000,000", "Varying Schema (79 to 85)", "Inconsistent Across Years",
        "Heterogeneous Network Features", "Different Timezones & Formats", "Disjoint Time Periods",
        "Inconsistent Identifiers", "Incompatible Topologies", "Extreme (All CIC Attacks)",
        "Yes (From 2018 Component)", "Yes (Multiple Tools)", "Yes (Multiple Botnets)", "Yes (Comprehensive)",
        "Yes (Extensive)", "Yes", "Yes",
        "Massive Benign Traffic", "Severe Discrepancies", "Severe Infs",
        "Millions of Multi-Year Duplicates", "Conflicting Class Definitions", "Multi-Version CICFlowMeter Drift",
        "Unstandardized Aggregation", "POOR (Temporal Gaps Between Years)", "POOR (Disjoint Sequences)",
        "Moderate (Harmonization Drift)", "Very High (>25 GB Combined)", "Scattered Across Repositories",
        "Multiple Academic Papers", "Mixed Academic Licenses", "RISK OF DOMAIN FINGERPRINTING"
    ]),
    # Cand F: BigFlow-NIDS
    ("F", "BigFlow-NIDS (Mendeley 2026)", [
        "Verified Secondary Derivative", "Mendeley Data Repository (2026)", ">20,000,000", "Harmonized Subset (~30-40)", "Pre-Cleaned",
        "Generalized NetFlow Telemetry", "Standardized Epoch Floats", "Artificially Concatenated",
        "Abstracted Flow Tuples", "Abstracted Host IDs", "High (Merged Benchmarks)",
        "Partial", "Yes", "Yes", "Yes",
        "Yes", "Yes", "Yes",
        ">85% Benign", "0 (Cleaned)", "0 (Cleaned)",
        "Deduplicated", "Harmonized Class Mappings", "Standardized Exporter",
        "Parquet Formatted", "Moderate (Cross-Dataset Gaps)", "Moderate",
        "Moderate (Simplified Taxonomy)", "High (~5 GB Parquet)", "Open via Mendeley Data",
        "Recent 2026 Dataset Publication", "Creative Commons Attribution", "GOOD FOR CROSS-DATASET VALIDATION"
    ]),
    # Cand G: DARPA 1998
    ("G", "DARPA 1998 (Week 1 / Week 2)", [
        "Verified Historical PCAP", "DARPA / MIT Lincoln Lab (1998)", "190,375 Windows (Week 1)", "47 Extracted Features", "Extracted via Scapy",
        "Simulated 1998 Packet Telemetry", "Epoch Timestamps (1998)", "Continuous 10s Windows",
        "Simulated SunOS Network Tuples", "Known Solaris Host IPs", "Very Low (Obsolete 1998 Exploits)",
        "No Modern Infiltration", "Telnet dict_simple Only", "None", "Smurf, Neptune (SYN flood), Teardrop, PoD",
        "None (Modern DDoS Absent)", "None (Web Attacks Absent)", "Portsweep Only",
        "189,032 Windows (99.3%)", "0", "0",
        "0 (Continuous Window States)", "Verified via BSM Audit Logs", "Manual Feature Extraction",
        "Extracted to Parquet", "POOR (Synthetically Scripted 1998)", "POOR",
        "POOR (Obsolete Solarís Exploits)", "Lightweight (~25 MB Parquet)", "Public Domain (1998)",
        "Historically Seminal, Now Obsolete", "Public Domain", "UNSUITABLE FOR MODERN NIDS"
    ])
]

# Build dataframe
matrix_dict = {"Criterion": criteria}
for cid, cname, col_vals in rows:
    matrix_dict[f"Candidate {cid}: {cname}"] = col_vals

df_matrix = pd.DataFrame(matrix_dict)
df_matrix.to_csv("reports/dataset_selection/02_dataset_comparison.csv", index=False)
print("Saved 02_dataset_comparison.csv (33 criteria x 7 candidates)")
