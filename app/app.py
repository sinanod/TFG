from flask import Flask, render_template, make_response
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
from fpdf import FPDF
from security_evaluator import generate_security_report

app = Flask(__name__)
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')

# --------------------------
# Cargar datos de auditoría
# --------------------------
report_data = generate_security_report()
resources = report_data['resources']
checks = report_data['checks']

# --------------------------
# Dashboard Interactivo
# --------------------------
# Preparar DataFrame de VMs
vms = resources['vms']
if vms:
    df_vms = pd.DataFrame({
        'Nombre_VM': [vm['name'] for vm in vms],
        'Cifrado_Disco': [
            'Sí' if 'Sin cifrado' not in vm['disk_encryption'][0] else 'No'
            for vm in vms
        ],
        'Diagnóstico_Boot': [
            'Habilitado' if 'Deshabilitados' not in vm['boot_diagnostics'] else 'Deshabilitado'
            for vm in vms
        ],
    })
else:
    df_vms = pd.DataFrame(columns=['Nombre_VM', 'Cifrado_Disco', 'Diagnóstico_Boot'])

fig_cifrado_discos = px.bar(
    df_vms,
    x='Nombre_VM',
    y='Cifrado_Disco',
    title='Estado de Cifrado de Discos en VMs'
)

fig_diagnostics = px.pie(
    df_vms,
    names='Diagnóstico_Boot',
    title='Diagnósticos de Arranque (VMs)'
)

# Layout del Dashboard
dash_app.layout = html.Div([
    html.H1("Dashboard de Seguridad de Azure", style={'textAlign': 'center'}),
    html.H2("Máquinas Virtuales", style={'textAlign': 'left'}),
    dcc.Graph(id='fig_cifrado_discos', figure=fig_cifrado_discos),
    dcc.Graph(id='fig_diagnostics', figure=fig_diagnostics),
])

# --------------------------
# Rutas de Flask
# --------------------------
@app.route('/')
def index():
    return render_template('index.html', resources=resources, checks=checks)

@app.route('/download_report')
def download_report():
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def add_title(text):
        pdf.set_font('Arial', 'B', 18)
        pdf.cell(0, 10, text, ln=True, align='C')
        pdf.ln(5)

    def add_section_title(text):
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 8, text, ln=True)
        pdf.ln(3)

    def add_separator():
        pdf.set_draw_color(150, 150, 150)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

    def add_checks_table(checks_list):
        pdf.set_font('Arial', 'B', 11)
        headers = ['Regla', 'Recurso', 'Estado', 'Criticidad', 'Normas', 'Recomendación']
        col_widths = [30, 50, 20, 25, 35, 30]
        col_aligns = ['C', 'L', 'C', 'C', 'L', 'L']
        line_height = 5

        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 8, header, border=1, align='C')
        pdf.ln()
        pdf.set_font('Arial', '', 9)

        for check in checks_list:
            row = [
                check.get('name', ''),
                check.get('resource', ''),
                "APROBADO" if check.get('passed') else "FALLIDO",
                check.get('criticality', 'Desconocida'),
                ", ".join(check.get('compliance', [])),
                check.get('recommendation', '')
            ]

            max_lines = 1
            for i, text in enumerate(row):
                width = col_widths[i]
                words = str(text).split()
                lines = 1
                line_width = 0
                for word in words:
                    w = pdf.get_string_width(word + ' ')
                    if line_width + w > width:
                        lines += 1
                        line_width = w
                    else:
                        line_width += w
                max_lines = max(max_lines, lines)

            row_height = max_lines * line_height
            x_start = pdf.get_x()
            y_start = pdf.get_y()

            for i, value in enumerate(row):
                pdf.set_xy(x_start + sum(col_widths[:i]), y_start)
                if i == 2:
                    pdf.set_fill_color(200, 255, 200) if check.get('passed') else pdf.set_fill_color(255, 200, 200)
                    pdf.multi_cell(col_widths[i], line_height, value, border=1, align=col_aligns[i], fill=True)
                    pdf.set_fill_color(255, 255, 255)
                else:
                    pdf.multi_cell(col_widths[i], line_height, str(value), border=1, align=col_aligns[i])

            pdf.set_y(y_start + row_height)

    add_title('Reporte de Seguridad de Azure')

    for section in ['vms', 'sql', 'storage', 'iam']:
        add_separator()
        add_section_title(f"Checks de {section.upper()}")
        add_checks_table(checks[section])

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=security_report.pdf'
    return response

if __name__ == "__main__":
    app.run(debug=True)
