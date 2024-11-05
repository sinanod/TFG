from flask import Flask, render_template, make_response
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
from fpdf import FPDF
from security_evaluator import generate_security_report

app = Flask(__name__)

# Crear la aplicación Dash y asociarla con la instancia de Flask
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')

# Generar los datos del reporte y preparar los gráficos
report_data = generate_security_report()

# Si hay datos, se convierten en un DataFrame para facilitar la visualización
vms = report_data['vms']
if not vms:
    df_vms = pd.DataFrame()  # Si no hay VMs, crear un DataFrame vacío
else:
    data = {
        'Nombre_VM': [vm['name'] for vm in vms],
        'Cifrado_Disco': ['Sí' if 'cumple' in enc[0].lower() else 'No' for vm in vms for enc in
                          [vm['disk_encryption']]],
        'Diagnóstico_Boot': ['Habilitado' if 'habilitados' in vm['boot_diagnostics'].lower() else 'Deshabilitado' for vm
                             in vms],
    }
    df_vms = pd.DataFrame(data)

# Crear gráficos usando Plotly Express
fig_cifrado_discos = px.bar(
    df_vms,
    x='Nombre_VM',
    y='Cifrado_Disco',
    title='Estado del Cifrado de Discos por Máquina Virtual',
    color='Cifrado_Disco',
    barmode='group'
)

fig_diagnostics = px.pie(
    df_vms,
    names='Diagnóstico_Boot',
    title='Estado de los Diagnósticos de Arranque de las Máquinas Virtuales'
)

# Añadir gráficos y contenido a la app de Dash
dash_app.layout = html.Div([
    html.H1("Dashboard de Seguridad de Azure", style={'textAlign': 'center'}),
    dcc.Graph(
        id='fig_cifrado_discos',
        figure=fig_cifrado_discos
    ),
    dcc.Graph(
        id='fig_diagnostics',
        figure=fig_diagnostics
    ),
])


@app.route('/')
def index():
    report_data = generate_security_report()
    report = report_data['vms']
    roles_permissions = report_data['roles_and_permissions']
    nsg_rules = []  # Implementa cómo obtener las reglas NSG
    change_history = []  # Historial de cambios de Azure

    return render_template('index.html', report=report, roles_permissions=roles_permissions,
                           change_history=change_history)


@app.route('/download_report')
def download_report():
    report_data = generate_security_report()

    if report_data['status'] == 'error':
        return "No se pudo generar el informe de seguridad.", 500

    # Crear el PDF usando FPDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Título principal
    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(0, 114, 188)  # Azul estilo Azure
    pdf.cell(0, 10, "Reporte de Seguridad de Azure", ln=True, align='C')
    pdf.ln(10)

    # Subtítulo
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Detalles de las Máquinas Virtuales", ln=True, align='L')
    pdf.ln(5)

    # Información de cada VM
    for vm in report_data['vms']:
        # Nombre de la VM
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f"Máquina Virtual: {vm['name']}", ln=True)
        pdf.ln(5)

        # Información sobre el cifrado de discos
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, "Estado del Cifrado de Disco:", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)

        for status in vm['disk_encryption']:
            pdf.cell(0, 10, f" - {status}", ln=True)

        pdf.ln(5)

        # Estado del Firewall
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, "Estado del Firewall:", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f" - {vm['firewall']}", ln=True)
        pdf.ln(5)

        # Diagnósticos de Arranque
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, "Diagnósticos de Arranque:", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f" - {vm['boot_diagnostics']}", ln=True)
        pdf.ln(10)

        # Línea separadora
        pdf.set_draw_color(200, 200, 200)  # Gris claro
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(10)

    # Crear la respuesta para el navegador
    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=security_report.pdf'
    return response


if __name__ == "__main__":
    app.run(debug=True)
