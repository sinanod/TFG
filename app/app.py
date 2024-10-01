# app.py
from flask import Flask, render_template
import security_evaluator

app = Flask(__name__)


@app.route("/")
def index():
    # Generar reporte de seguridad usando las funciones de security_evaluator
    result = security_evaluator.generate_security_report()

    # Transformar los datos para que coincidan con el formato esperado
    report = []
    if result['status'] == 'success':  # Verificar si el informe se generó correctamente
        for vm in result['vms']:
            encryption_status = ', '.join(vm['disk_encryption'])  # Unir mensajes de cifrado en una cadena
            nsg_status = ', '.join(vm['nsg'])  # Unir nombres de NSG en una cadena

            report.append({
                "vm_name": vm['name'],
                "encryption_status": encryption_status,
                "nsg_status": nsg_status
            })

    return render_template("index.html", report=report)


if __name__ == "__main__":
    app.run(debug=True)
