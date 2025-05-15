import json
import argparse
from security_evaluator import generate_security_report

def main():
    parser = argparse.ArgumentParser(description="Ejecuta evaluación de seguridad de Azure.")
    parser.add_argument('--output', choices=['json', 'md'], default='json', help='Formato de salida del reporte')
    args = parser.parse_args()

    report = generate_security_report()

    if args.output == 'json':
        print(json.dumps(report, indent=4, ensure_ascii=False))

    elif args.output == 'md':
        with open("security_report.md", "w", encoding="utf-8") as f:
            f.write("# Reporte de Seguridad de Azure\n\n")

            for section, check_list in report['checks'].items():
                f.write(f"## Checks de {section.upper()}\n\n")
                for check in check_list:
                    estado = "✅ Aprobado" if check.get('passed') else "❌ Fallido"
                    f.write(f"**Regla**: {check['name']}\n\n")
                    f.write(f"**Recurso**: {check['resource']}\n\n")
                    f.write(f"**Estado**: {estado}\n\n")
                    f.write(f"**Criticidad**: {check.get('criticality', 'Desconocida')}\n\n")
                    f.write(f"**Normas**: {', '.join(check.get('compliance', []))}\n\n")
                    f.write(f"**Recomendación**: {check['recommendation']}\n\n")
                    f.write("---\n\n")

if __name__ == "__main__":
    main()
