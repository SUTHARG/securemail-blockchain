"""E2: Detection Accuracy Evaluation.

Evaluates per-rule Precision, Recall, True Positives (TP), False Positives (FP),
and False Negatives (FN) across all lab scenarios with the confusion list.
Outputs:
- eval/results/e2_detection_accuracy.csv
- eval/results/e2_detection_accuracy.md
"""
import csv
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.compare_labels import analyze_pcap

CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
LABELS_DIR = REPO_ROOT / "lab" / "labels"
RESULTS_DIR = REPO_ROOT / "eval" / "results"

TIER1_RULES = [
    "R01", "R02", "R03", "R06", "R08", "R09",
    "R11", "R12", "R13", "R15", "R16", "R19",
]


def run_e2() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Execute E2 detection accuracy experiment."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    pcap_files = sorted(CAPTURES_DIR.glob("*.pcap"))

    rule_stats: Dict[str, Dict[str, int]] = {
        r: {"tp": 0, "fp": 0, "fn": 0} for r in TIER1_RULES
    }
    confusion_list: List[Dict[str, Any]] = []

    for pcap in pcap_files:
        scenario = pcap.stem
        label_file = LABELS_DIR / f"{scenario}.json"
        if not label_file.exists():
            continue

        label_data = json.loads(label_file.read_text(encoding="utf-8"))
        expected_rules = {ef["ruleId"] for ef in label_data.get("expectedFindings", [])}

        actual_findings = analyze_pcap(pcap)
        actual_rules = {f.ruleId for f in actual_findings}

        # Check per Tier 1 rule
        for r in TIER1_RULES:
            in_expected = r in expected_rules
            in_actual = r in actual_rules

            if in_expected and in_actual:
                rule_stats[r]["tp"] += 1
            elif not in_expected and in_actual:
                rule_stats[r]["fp"] += 1
                confusion_list.append({
                    "scenario": scenario,
                    "ruleId": r,
                    "type": "False Positive (Unexpected)",
                    "detail": f"Engine flagged {r} but label did not expect it",
                })
            elif in_expected and not in_actual:
                rule_stats[r]["fn"] += 1
                confusion_list.append({
                    "scenario": scenario,
                    "ruleId": r,
                    "type": "False Negative (Missing)",
                    "detail": f"Label expected {r} but engine did not flag it",
                })

    rule_rows = []
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for r in TIER1_RULES:
        tp = rule_stats[r]["tp"]
        fp = rule_stats[r]["fp"]
        fn = rule_stats[r]["fn"]
        total_tp += tp
        total_fp += fp
        total_fn += fn

        prec = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        rec = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 1.0

        rule_rows.append({
            "rule_id": r,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": f"{prec:.2f}",
            "recall": f"{rec:.2f}",
            "f1_score": f"{f1:.2f}",
        })

    # Write CSV
    csv_path = RESULTS_DIR / "e2_detection_accuracy.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "tp", "fp", "fn", "precision", "recall", "f1_score"])
        writer.writeheader()
        writer.writerows(rule_rows)

    # Write Markdown
    md_path = RESULTS_DIR / "e2_detection_accuracy.md"
    overall_prec = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 1.0
    overall_rec = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 1.0

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Experiment E2: Detection Accuracy across Lab Scenarios\n\n")
        f.write(f"**Overall Accuracy:** Precision: **{overall_prec:.2f}**, Recall: **{overall_rec:.2f}** (TP={total_tp}, FP={total_fp}, FN={total_fn})\n\n")
        f.write("| Rule ID | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for row in rule_rows:
            f.write(f"| {row['rule_id']} | {row['tp']} | {row['fp']} | {row['fn']} | {row['precision']} | {row['recall']} | {row['f1_score']} |\n")

        f.write("\n### Confusion List\n\n")
        if confusion_list:
            f.write("| Scenario | Rule ID | Type | Detail |\n")
            f.write("|---|---|---|---|\n")
            for c in confusion_list:
                f.write(f"| {c['scenario']} | {c['ruleId']} | {c['type']} | {c['detail']} |\n")
        else:
            f.write("No false positives or false negatives observed across all 17 lab scenarios (100% precision and recall).\n")

    return rule_rows, confusion_list


if __name__ == "__main__":
    rows, confusion = run_e2()
    print(f"E2 Complete: {len(rows)} rules evaluated. Confusion items: {len(confusion)}")
