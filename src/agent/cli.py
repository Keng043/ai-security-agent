import argparse
from .http_scanner import scan_http
from .report import write_json
from .pipeline import AssessmentPipeline

def main() -> None:
    parser = argparse.ArgumentParser(description="AI Security Agent - authorized HTTP assessment")
    parser.add_argument("url", help="Authorized HTTP/HTTPS target, preferably localhost for the lab")
    parser.add_argument("--report", default="security-report.json")
    args = parser.parse_args()
    target, findings = scan_http(args.url)
    result = AssessmentPipeline().run(target, findings)
    write_json(args.report, result["target"], findings)
    print(f"Target: {target['url']}")
    print(f"Status: {target['status']}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.title}")
    print(f"Report: {args.report}")

if __name__ == "__main__":
    main()
