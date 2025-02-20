from flask import Flask, render_template, make_response
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
from fpdf import FPDF
from security_evaluator import generate_security_report

app = Flask(__name__)

# Integración con Dash
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')

# Generar los datos del reporte de seguridad
report_data = generate_security_report()
vms = report_data['vms']

# Prepara los datos para las gráficas de Plotly
if vms:
    # Ejemplo de dataframe simplificado
    data = {
        'Nombre_VM': [vm['name'] for vm in vms],
        'Cifrado_Disco': [
            'Sí' if 'cumple' in enc[0].lower() else 'No'
            for vm in vms
            for enc in [vm['disk_encryption']]
        ],
        'Diagnóstico_Boot': [
            'Habilitado' if 'habilitados' in vm['boot_diagnostics'].lower() else 'Deshabilitado'
            for vm in vms
        ],
    }
    df_vms = pd.DataFrame(data)
else:
    # Si no hay VMs o datos devueltos
    df_vms = pd.DataFrame(columns=['Nombre_VM', 'Cifrado_Disco', 'Diagnóstico_Boot'])

# Gráficos con Plotly
fig_cifrado_discos = px.bar(
    df_vms,
    x='Nombre_VM',
    y='Cifrado_Disco',
    title='Estado del Cifrado de Discos'
)

fig_diagnostics = px.pie(
    df_vms,
    names='Diagnóstico_Boot',
    title='Diagnósticos de Arranque'
)

# Diseño del dashboard de Dash
dash_app.layout = html.Div([
    html.H1("Dashboard de Seguridad de Azure", style={'textAlign': 'center'}),
    dcc.Graph(id='fig_cifrado_discos', figure=fig_cifrado_discos),
    dcc.Graph(id='fig_diagnostics', figure=fig_diagnostics),
])

@app.route('/')
def index():
    """Página principal que muestra un resumen en tablas."""
    return render_template('index.html', report=vms)

@app.route('/download_report')
def download_report():
    """Genera un reporte PDF usando FPDF con la información de las VMs."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "Reporte de Seguridad de Azure", ln=True, align='C')
    pdf.ln(5)

    # Recorrer las VMs y añadir información al PDF
    for vm in vms:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"VM: {vm['name']}", ln=True)

        pdf.set_font("Arial", "", 12)
        disk_status = ", ".join(vm.get('disk_encryption', []))
        pdf.cell(0, 10, f"  - Cifrado de Disco: {disk_status}", ln=True)
        pdf.cell(0, 10, f"  - Firewall: {vm.get('firewall', 'No evaluado')}", ln=True)
        pdf.cell(0, 10, f"  - Diagnósticos de Arranque: {vm.get('boot_diagnostics', 'Deshabilitado')}", ln=True)
        pdf.ln(5)

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=security_report.pdf'
    return response

if __name__ == "__main__":
    app.run(debug=True)
