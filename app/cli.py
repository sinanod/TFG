import json
import argparse
from security_evaluator import generate_security_report


def main():
    parser = argparse.ArgumentParser(description='Ejecuta la evaluación de seguridad en Azure')
    parser.add_argument('--output', choices=['json', 'md'], default='json',
                        help='Formato de salida del reporte (json o md)')
    args = parser.parse_args()

    report = generate_security_report()

    if args.output == 'json':
        print(json.dumps(report, indent=4))
    elif args.output == 'md':
        with open("security_report.md", "w", encoding='utf-8') as f:
            f.write("# Reporte de Seguridad de Azure\n\n")
            for key, values in report.items():
                f.write(f"## {key.capitalize()}\n\n")
                for value in values:
                    f.write(f"- {json.dumps(value, indent=2, ensure_ascii=False)}\n\n")


if __name__ == "__main__":
    main()
